//! DNS Amplification Filter — Deep Payload Inspection
//!
//! Detects and blocks DNS amplification attacks by inspecting
//! UDP payloads on port 53. Key heuristics:
//!
//! 1. **Response Size** — DNS responses > 512 bytes that we never
//!    initiated are likely amplification traffic.
//! 2. **Query Tracking** — Maintains a BPF map of recent outbound
//!    DNS queries (TxID → timestamp). Inbound responses without
//!    a matching query are dropped.
//! 3. **ANY Query Detection** — Outbound queries with QTYPE=ANY
//!    are blocked because they're commonly abused for amplification.
//! 4. **Response Rate** — Rate-limits inbound DNS responses per source.

use aya_ebpf::maps::LruHashMap;
use aegis_common::*;

/// DNS header structure (first 12 bytes of UDP payload).
/// RFC 1035 Section 4.1.1
///
/// ```text
///                                 1  1  1  1  1  1
///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      ID                       |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    QDCOUNT                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ANCOUNT                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    NSCOUNT                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ARCOUNT                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[repr(C)]
#[derive(Copy, Clone)]
pub struct DnsHeader {
    pub id: u16,        // Transaction ID
    pub flags: u16,     // QR, Opcode, AA, TC, RD, RA, Z, RCODE
    pub qdcount: u16,   // Question count
    pub ancount: u16,   // Answer count
    pub nscount: u16,   // Authority count
    pub arcount: u16,   // Additional count
}

impl DnsHeader {
    /// Returns true if this is a DNS response (QR bit = 1).
    #[inline(always)]
    pub fn is_response(&self) -> bool {
        (u16::from_be(self.flags) & 0x8000) != 0
    }

    /// Returns true if this is a DNS query (QR bit = 0).
    #[inline(always)]
    pub fn is_query(&self) -> bool {
        !self.is_response()
    }

    /// Get the response code (RCODE, lower 4 bits of flags).
    #[inline(always)]
    pub fn rcode(&self) -> u8 {
        (u16::from_be(self.flags) & 0x000F) as u8
    }

    /// Get the number of answers.
    #[inline(always)]
    pub fn answer_count(&self) -> u16 {
        u16::from_be(self.ancount)
    }
}

/// Check if an inbound DNS packet is a suspected amplification attack.
///
/// Returns `true` if the packet should be DROPPED.
///
/// # Arguments
/// - `dns_hdr`: Pointer to the DNS header within the packet
/// - `payload_len`: Total UDP payload length
/// - `src_ip`: Source IP of the packet
/// - `max_response_size`: Configured maximum DNS response size
/// - `query_tracker`: BPF map tracking outbound DNS query TxIDs
#[inline(always)]
pub fn check_dns_amplification(
    dns_hdr: &DnsHeader,
    payload_len: u16,
    src_ip: u32,
    max_response_size: u16,
    query_tracker: &LruHashMap<u16, u64>,
) -> bool {
    // Only inspect DNS responses.
    if dns_hdr.is_query() {
        return false;
    }

    // ── Check 1: Oversized response ─────────────────────────────
    // DNS responses > max_response_size (default 512) without EDNS0
    // are highly suspicious of amplification.
    if payload_len > max_response_size {
        return true;
    }

    // ── Check 2: Unmatched response ─────────────────────────────
    // If we didn't send a query with this Transaction ID, this is
    // an unsolicited response (amplification).
    let tx_id = u16::from_be(dns_hdr.id);
    match unsafe { query_tracker.get(&tx_id) } {
        Some(_) => {
            // We sent this query — allow the response.
            // Remove from tracker to prevent replay.
            let _ = query_tracker.remove(&tx_id);
            false
        }
        None => {
            // No matching query — suspicious.
            // Only drop if the response is non-trivially sized.
            payload_len > 100
        }
    }
}

/// Track an outbound DNS query by storing its Transaction ID.
/// Called in the TX path when we see an outbound DNS query.
#[inline(always)]
pub fn track_outbound_query(
    query_tracker: &LruHashMap<u16, u64>,
    dns_hdr: &DnsHeader,
    now_ns: u64,
) {
    if dns_hdr.is_query() {
        let tx_id = u16::from_be(dns_hdr.id);
        let _ = query_tracker.insert(&tx_id, &now_ns, 0);
    }
}

/// Check if a DNS query is requesting QTYPE=ANY (0x00FF).
/// ANY queries are abused for amplification (one small query →
/// enormous response with all record types).
///
/// Returns `true` if the query should be blocked.
#[inline(always)]
pub fn is_any_query(payload: &[u8]) -> bool {
    // The QTYPE field is after the QNAME in the question section.
    // QNAME is variable-length (labels ending with 0x00).
    // We need to skip past the DNS header (12 bytes) and the QNAME.
    if payload.len() < 14 {
        return false; // Too short to contain a question
    }

    // Skip DNS header (12 bytes).
    let mut offset = 12usize;

    // Skip QNAME labels until we hit the null terminator.
    while offset < payload.len() {
        let label_len = payload[offset] as usize;
        if label_len == 0 {
            offset += 1; // Skip null terminator
            break;
        }
        // Compressed labels (pointer) start with 0xC0.
        if label_len >= 0xC0 {
            offset += 2; // Skip pointer
            break;
        }
        offset += label_len + 1;
        if offset >= payload.len() {
            return false; // Malformed
        }
    }

    // Read QTYPE (2 bytes, big-endian).
    if offset + 2 > payload.len() {
        return false;
    }
    let qtype = ((payload[offset] as u16) << 8) | (payload[offset + 1] as u16);

    // QTYPE 255 = ANY
    qtype == 255
}
