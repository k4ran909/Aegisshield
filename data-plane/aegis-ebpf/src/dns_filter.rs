//! DNS Amplification Filter — Deep Payload Inspection
//!
//! Detects and blocks DNS amplification attacks by inspecting
//! UDP payloads on port 53.

use aya_ebpf::maps::LruHashMap;

/// DNS header structure (first 12 bytes of UDP payload, RFC 1035).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
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
/// Returns `true` if the packet should be DROPPED.
#[inline(always)]
pub fn check_dns_amplification(
    dns_hdr: &DnsHeader,
    payload_len: u16,
    _src_ip: u32,
    max_response_size: u16,
    query_tracker: &LruHashMap<u16, u64>,
) -> bool {
    if dns_hdr.is_query() {
        return false;
    }

    // Oversized response check.
    if payload_len > max_response_size {
        return true;
    }

    // Unmatched response check.
    let tx_id = u16::from_be(dns_hdr.id);
    match unsafe { query_tracker.get(&tx_id) } {
        Some(_) => {
            let _ = query_tracker.remove(&tx_id);
            false
        }
        None => payload_len > 100,
    }
}

/// Track an outbound DNS query by storing its Transaction ID.
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
#[inline(always)]
pub fn is_any_query(payload: &[u8]) -> bool {
    if payload.len() < 14 {
        return false;
    }

    let mut offset = 12usize;

    while offset < payload.len() {
        let label_len = payload[offset] as usize;
        if label_len == 0 {
            offset += 1;
            break;
        }
        if label_len >= 0xC0 {
            offset += 2;
            break;
        }
        offset += label_len + 1;
        if offset >= payload.len() {
            return false;
        }
    }

    if offset + 2 > payload.len() {
        return false;
    }
    let qtype = ((payload[offset] as u16) << 8) | (payload[offset + 1] as u16);
    qtype == 255
}
