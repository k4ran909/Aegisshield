//! GRE Flood Filter — Protocol 47 Rate Limiting
//!
//! Rate-limits GRE packets per source IP, validates GRE header version,
//! and optionally enforces a tunnel endpoint whitelist.

use aegis_common::*;
use aya_ebpf::maps::{HashMap, LruHashMap};

/// GRE header (RFC 2784).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct GreHeader {
    pub flags_version: u16,
    pub protocol_type: u16,
}

impl GreHeader {
    /// Extract version bits (lower 3 bits of first 16-bit word).
    #[inline(always)]
    pub fn version(&self) -> u8 {
        (u16::from_be(self.flags_version) & 0x0007) as u8
    }

    /// Check if checksum bit is set.
    #[inline(always)]
    pub fn has_checksum(&self) -> bool {
        (u16::from_be(self.flags_version) & 0x8000) != 0
    }
}

/// Per-IP GRE rate state.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct GreRateState {
    pub count: u64,
    pub window_start_ns: u64,
}

/// Check if a GRE packet should be dropped.
/// Returns `true` if the packet should be DROPPED.
#[inline(always)]
pub fn check_gre(
    rate_map: &LruHashMap<u32, GreRateState>,
    tunnel_whitelist: &HashMap<u32, u8>,
    src_ip: u32,
    gre_hdr: &GreHeader,
    threshold: u64,
    now_ns: u64,
) -> bool {
    // GRE version must be 0 (standard) or 1 (PPTP).
    let version = gre_hdr.version();
    if version > 1 {
        return true;
    }

    // Tunnel endpoint whitelist enforcement.
    if unsafe { tunnel_whitelist.get(&0u32) }.is_some() {
        if unsafe { tunnel_whitelist.get(&src_ip) }.is_none() {
            return true;
        }
    }

    // Rate limiting.
    match unsafe { rate_map.get(&src_ip) } {
        Some(state) => {
            let elapsed = now_ns.saturating_sub(state.window_start_ns);

            if elapsed > RATE_WINDOW_NS {
                let new_state = GreRateState {
                    count: 1,
                    window_start_ns: now_ns,
                };
                let _ = rate_map.insert(&src_ip, &new_state, 0);
                false
            } else {
                let new_count = state.count + 1;
                let new_state = GreRateState {
                    count: new_count,
                    window_start_ns: state.window_start_ns,
                };
                let _ = rate_map.insert(&src_ip, &new_state, 0);
                new_count > threshold
            }
        }
        None => {
            let new_state = GreRateState {
                count: 1,
                window_start_ns: now_ns,
            };
            let _ = rate_map.insert(&src_ip, &new_state, 0);
            false
        }
    }
}
