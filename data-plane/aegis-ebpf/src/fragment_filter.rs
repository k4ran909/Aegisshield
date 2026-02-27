//! IP Fragment Attack Filter
//!
//! Drops all IP fragments by default (modern traffic uses PMTUD).
//! Also provides selective filtering for specific fragment attacks:
//! teardrop, fragment floods, first-fragment bypass, tiny fragments.

/// Check if the packet is a fragment (MF flag set or frag offset != 0).
#[inline(always)]
pub fn is_fragment(flags_frag_offset: u16) -> bool {
    let val = u16::from_be(flags_frag_offset);
    let mf = (val & 0x2000) != 0;
    let frag_offset = val & 0x1FFF;
    mf || frag_offset != 0
}

/// Check if this is the first fragment (has ports but MF=1).
#[inline(always)]
pub fn is_first_fragment(flags_frag_offset: u16) -> bool {
    let val = u16::from_be(flags_frag_offset);
    let mf = (val & 0x2000) != 0;
    let frag_offset = val & 0x1FFF;
    mf && frag_offset == 0
}

/// Check if this is a subsequent (non-first) fragment.
#[inline(always)]
pub fn is_subsequent_fragment(flags_frag_offset: u16) -> bool {
    let val = u16::from_be(flags_frag_offset);
    let frag_offset = val & 0x1FFF;
    frag_offset != 0
}

/// Detect tiny fragment attack (first fragment too small for L4 header).
#[inline(always)]
pub fn is_tiny_fragment(flags_frag_offset: u16, ip_total_length: u16) -> bool {
    if is_first_fragment(flags_frag_offset) {
        u16::from_be(ip_total_length) < 60
    } else {
        false
    }
}

/// Fragment filtering decision — drops ALL fragments (aggressive but safe).
/// Returns `true` if the fragment should be DROPPED.
#[inline(always)]
pub fn should_drop_fragment(flags_frag_offset: u16, _ip_total_length: u16) -> bool {
    if !is_fragment(flags_frag_offset) {
        return false;
    }
    true
}

/// Selective fragment filter — only drops suspicious fragments.
/// Returns `true` if the fragment should be DROPPED.
#[inline(always)]
pub fn should_drop_fragment_selective(flags_frag_offset: u16, ip_total_length: u16) -> bool {
    if !is_fragment(flags_frag_offset) {
        return false;
    }

    if is_tiny_fragment(flags_frag_offset, ip_total_length) {
        return true;
    }

    if is_subsequent_fragment(flags_frag_offset) {
        return true;
    }

    false
}
