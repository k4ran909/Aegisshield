//! GRE Flood Filter — Protocol 47 Rate Limiting
//!
//! GRE (Generic Routing Encapsulation, IP protocol 47) is commonly
//! used for tunneling but is also exploited for volumetric floods.
//! Attackers send massive amounts of GRE traffic to overwhelm the
//! target's tunnel decapsulation or simply saturate bandwidth.
//!
//! This filter:
//! 1. Rate-limits GRE packets per source IP
//! 2. Validates the GRE header version field
//! 3. Optionally allows only whitelisted tunnel endpoints

use aya_ebpf::maps::{LruHashMap, HashMap};
use aegis_common::*;

/// GRE header (RFC 2784).
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |C|       Reserved0       | Ver |         Protocol Type         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C)]
#[derive(Copy, Clone)]
pub struct GreHeader {
    pub flags_version: u16,  // Flags (C, Reserved0) and Version
    pub protocol_type: u16,  // EtherType of encapsulated payload
}

impl GreHeader {
    /// Extract version bits (lower 3 bits of first 16-bit word).
    #[inline(always)]
    pub fn version(&self) -> u8 {
        (u16::from_be(self.flags_version) & 0x0007) as u8
    }

    /// Check if checksum bit is set (bit 15 of first word).
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
///
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
    // ── Check 1: GRE version must be 0 (standard) or 1 (PPTP) ──
    let version = gre_hdr.version();
    if version > 1 {
        return true; // Invalid GRE version — drop
    }

    // ── Check 2: Tunnel endpoint whitelist ──────────────────────
    // If a whitelist exists and this IP is not in it, drop.
    // An empty whitelist means no whitelist enforcement.
    if let Some(_) = unsafe { tunnel_whitelist.get(&0u32) } {
        // Whitelist is active — check if source IP is whitelisted.
        if unsafe { tunnel_whitelist.get(&src_ip) }.is_none() {
            return true; // Not whitelisted — drop
        }
    }

    // ── Check 3: Rate limiting ──────────────────────────────────
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
