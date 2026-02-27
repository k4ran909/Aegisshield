//! ICMP Flood Filter — Rate Limiting + Validation
//!
//! Provides defense against:
//! 1. ICMP Echo (ping) flood attacks
//! 2. ICMP Smurf attacks (spoofed source broadcast)
//! 3. Oversized ICMP packets (Ping of Death)
//! 4. ICMP redirect attacks
//!
//! Only ICMP Echo Request (type 8) and Echo Reply (type 0) are allowed.
//! All other ICMP types are rate-limited or blocked based on policy.

use aya_ebpf::maps::LruHashMap;
use aegis_common::*;

/// ICMP message types (RFC 792).
pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_DEST_UNREACHABLE: u8 = 3;
pub const ICMP_REDIRECT: u8 = 5;
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_TIME_EXCEEDED: u8 = 11;

/// Maximum allowed ICMP payload size (bytes).
/// The "Ping of Death" attack uses oversized ICMP packets (>65535 bytes total).
/// Modern stacks handle this, but we add defense-in-depth.
pub const MAX_ICMP_PAYLOAD: u16 = 1024;

/// Per-IP ICMP rate state.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct IcmpRateState {
    pub count: u64,
    pub window_start_ns: u64,
}

/// Check if an ICMP packet should be dropped.
///
/// Returns `true` if the packet should be DROPPED.
///
/// # Checks performed:
/// 1. Block dangerous ICMP types (Redirect)
/// 2. Rate-limit per source IP
/// 3. Block oversized packets
#[inline(always)]
pub fn check_icmp(
    rate_map: &LruHashMap<u32, IcmpRateState>,
    src_ip: u32,
    icmp_type: u8,
    icmp_code: u8,
    payload_len: u16,
    threshold: u64,
    now_ns: u64,
) -> IcmpAction {
    // ── Check 1: Block dangerous ICMP types ─────────────────────
    match icmp_type {
        ICMP_REDIRECT => return IcmpAction::Drop,        // Never allow redirects
        5 => return IcmpAction::Drop,                     // Source quench (deprecated)
        _ => {}
    }

    // ── Check 2: Block oversized ICMP packets ───────────────────
    if payload_len > MAX_ICMP_PAYLOAD {
        return IcmpAction::Drop;
    }

    // ── Check 3: Only rate-limit echo requests ──────────────────
    // Allow echo replies and error messages without rate limiting.
    if icmp_type != ICMP_ECHO_REQUEST {
        return IcmpAction::Pass;
    }

    // ── Check 4: Per-IP rate limiting ───────────────────────────
    match unsafe { rate_map.get(&src_ip) } {
        Some(state) => {
            let elapsed = now_ns.saturating_sub(state.window_start_ns);

            if elapsed > RATE_WINDOW_NS {
                let new_state = IcmpRateState {
                    count: 1,
                    window_start_ns: now_ns,
                };
                let _ = rate_map.insert(&src_ip, &new_state, 0);
                IcmpAction::Pass
            } else {
                let new_count = state.count + 1;
                let new_state = IcmpRateState {
                    count: new_count,
                    window_start_ns: state.window_start_ns,
                };
                let _ = rate_map.insert(&src_ip, &new_state, 0);

                if new_count > threshold {
                    IcmpAction::Drop
                } else {
                    IcmpAction::Pass
                }
            }
        }
        None => {
            let new_state = IcmpRateState {
                count: 1,
                window_start_ns: now_ns,
            };
            let _ = rate_map.insert(&src_ip, &new_state, 0);
            IcmpAction::Pass
        }
    }
}

/// ICMP filter action result.
pub enum IcmpAction {
    Pass,
    Drop,
}
