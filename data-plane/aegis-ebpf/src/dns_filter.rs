//! DNS amplification heuristics for ingress filtering.

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
    #[inline(always)]
    pub fn is_response(&self) -> bool {
        (u16::from_be(self.flags) & 0x8000) != 0
    }

    #[inline(always)]
    pub fn is_query(&self) -> bool {
        !self.is_response()
    }

    #[inline(always)]
    pub fn answer_count(&self) -> u16 {
        u16::from_be(self.ancount)
    }
}

/// Check whether an ingress DNS packet looks like amplification traffic.
#[inline(always)]
pub fn check_dns_amplification(
    dns_hdr: &DnsHeader,
    payload_len: u16,
    max_response_size: u16,
) -> bool {
    if dns_hdr.is_query() {
        return false;
    }

    if payload_len > max_response_size {
        return true;
    }

    // Large answer fanout is uncommon for normal resolver traffic.
    dns_hdr.answer_count() > 32 && payload_len > 256
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
