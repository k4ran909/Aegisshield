//! IP Fragment Attack Filter
//!
//! Attackers use IP fragmentation to bypass XDP/firewall filters:
//! 1. **Teardrop** — Overlapping fragment offsets causing kernel crashes
//! 2. **Fragment flood** — Massive fragmented packets overwhelming reassembly
//! 3. **First-fragment bypass** — Only first fragment has port info, subsequent
//!    fragments slip past port-based filters
//! 4. **Tiny fragment** — Fragments so small they split the L4 header across
//!    multiple fragments, making port-based filtering impossible
//!
//! Policy: We drop ALL IP fragments in the XDP data plane since legitimate
//! modern traffic rarely uses IP fragmentation (Path MTU Discovery is standard).
//! If fragmentation is needed for specific flows, configure it via ACL rules.

use aegis_common::*;

/// Check the IP flags and fragment offset to determine if this is a fragment.
///
/// IPv4 header byte 6-7 contain:
/// - Bit 0: Reserved (0)
/// - Bit 1: DF (Don't Fragment)
/// - Bit 2: MF (More Fragments)
/// - Bits 3-15: Fragment Offset (in 8-byte units)
///
/// A packet is a fragment if:
/// - MF (More Fragments) flag is set, OR
/// - Fragment Offset is non-zero (this is a subsequent fragment)
#[inline(always)]
pub fn is_fragment(flags_frag_offset: u16) -> bool {
    let val = u16::from_be(flags_frag_offset);
    let mf = (val & 0x2000) != 0;         // More Fragments flag
    let frag_offset = val & 0x1FFF;        // Fragment offset field
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

/// Detect tiny fragment attack.
/// RFC 791 requires at least 8 bytes per fragment, but tiny fragments
/// can be used to split L4 headers (TCP: 20 bytes, UDP: 8 bytes)
/// across multiple fragments.
///
/// A first fragment with total IP length < 60 bytes is suspicious
/// because it can't contain a full IP header + L4 header.
#[inline(always)]
pub fn is_tiny_fragment(flags_frag_offset: u16, ip_total_length: u16) -> bool {
    if is_first_fragment(flags_frag_offset) {
        // First fragment should be large enough to contain at least
        // IP header (20 bytes) + TCP header (20 bytes) = 40 bytes minimum.
        // We use a threshold of 60 to account for IP options.
        u16::from_be(ip_total_length) < 60
    } else {
        false
    }
}

/// Fragment filtering decision.
///
/// Returns `true` if the fragment should be DROPPED.
///
/// # Policy:
/// - First fragments that are too tiny → DROP (tiny fragment attack)
/// - Subsequent fragments → DROP (can't apply L4 filters)
/// - Non-fragmented packets → PASS (handled by other filters)
#[inline(always)]
pub fn should_drop_fragment(flags_frag_offset: u16, ip_total_length: u16) -> bool {
    if !is_fragment(flags_frag_offset) {
        return false; // Not a fragment — let other filters handle it
    }

    // Drop ALL fragments by default (aggressive but safe policy).
    // Modern networks use Path MTU Discovery, so legitimate traffic
    // is almost never fragmented.
    true
}

/// Selective fragment filter — only drop suspicious fragments
/// while allowing legitimate ones. Less aggressive than `should_drop_fragment`.
///
/// Returns `true` if the fragment should be DROPPED.
#[inline(always)]
pub fn should_drop_fragment_selective(flags_frag_offset: u16, ip_total_length: u16) -> bool {
    if !is_fragment(flags_frag_offset) {
        return false;
    }

    // Always drop tiny fragments (likely attack).
    if is_tiny_fragment(flags_frag_offset, ip_total_length) {
        return true;
    }

    // Drop subsequent fragments (can't inspect ports).
    if is_subsequent_fragment(flags_frag_offset) {
        return true;
    }

    // First fragments with normal size are allowed (we can inspect ports).
    false
}
