//! ICMP Flood Filter — Rate Limiting + Validation
//!
//! Defends against ICMP echo floods, Smurf attacks, Ping of Death,
//! and ICMP redirect attacks. Only Echo Request/Reply are allowed;
//! dangerous types are blocked outright.

use aegis_common::*;
use aya_ebpf::maps::LruHashMap;

/// ICMP message types (RFC 792).
pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_DEST_UNREACHABLE: u8 = 3;
pub const ICMP_REDIRECT: u8 = 5;
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_TIME_EXCEEDED: u8 = 11;

/// Maximum allowed ICMP payload size (bytes).
pub const MAX_ICMP_PAYLOAD: u16 = 1024;

/// Per-IP ICMP rate state.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct IcmpRateState {
    pub count: u64,
    pub window_start_ns: u64,
}

/// ICMP filter action result.
pub enum IcmpAction {
    Pass,
    Drop,
}

/// Check if an ICMP packet should be dropped.
/// Returns IcmpAction::Drop if the packet should be dropped.
#[inline(always)]
pub fn check_icmp(
    rate_map: &LruHashMap<u32, IcmpRateState>,
    src_ip: u32,
    icmp_type: u8,
    _icmp_code: u8,
    payload_len: u16,
    threshold: u64,
    now_ns: u64,
) -> IcmpAction {
    // Block dangerous ICMP types.
    if icmp_type == ICMP_REDIRECT {
        return IcmpAction::Drop;
    }

    // Block oversized ICMP packets.
    if payload_len > MAX_ICMP_PAYLOAD {
        return IcmpAction::Drop;
    }

    // Only rate-limit echo requests.
    if icmp_type != ICMP_ECHO_REQUEST {
        return IcmpAction::Pass;
    }

    // threshold=0 means block ALL pings — server becomes invisible.
    if threshold == 0 {
        return IcmpAction::Drop;
    }

    // Per-IP rate limiting.
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
