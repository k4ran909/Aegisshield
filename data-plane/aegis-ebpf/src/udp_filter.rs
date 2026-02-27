//! UDP Flood Filter — Per-Source-IP Rate Limiting
//!
//! Uses a BPF LRU HashMap to track per-source-IP packet rates.
//! When the rate exceeds the configured threshold within the
//! time window, all subsequent UDP packets from that IP are dropped.
//!
//! The LRU map automatically evicts the oldest entry when full,
//! ensuring memory usage stays bounded even under heavy attack.

use aya_ebpf::maps::LruHashMap;
use aegis_common::*;

/// Per-IP UDP rate state tracked in the BPF map.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UdpRateState {
    pub count: u64,
    pub window_start_ns: u64,
}

/// Check if a UDP packet from the given source IP should be dropped.
///
/// Returns `true` if the packet should be DROPPED (rate exceeded).
#[inline(always)]
pub fn check_udp_rate(
    rate_map: &LruHashMap<u32, UdpRateState>,
    src_ip: u32,
    threshold: u64,
    now_ns: u64,
) -> bool {
    match unsafe { rate_map.get(&src_ip) } {
        Some(state) => {
            let elapsed = now_ns.saturating_sub(state.window_start_ns);

            if elapsed > RATE_WINDOW_NS {
                // Window expired — reset counter.
                let new_state = UdpRateState {
                    count: 1,
                    window_start_ns: now_ns,
                };
                let _ = rate_map.insert(&src_ip, &new_state, 0);
                false
            } else {
                // Still within window — increment and check.
                let new_count = state.count + 1;
                let new_state = UdpRateState {
                    count: new_count,
                    window_start_ns: state.window_start_ns,
                };
                let _ = rate_map.insert(&src_ip, &new_state, 0);
                new_count > threshold
            }
        }
        None => {
            // First packet from this IP — initialize tracking.
            let new_state = UdpRateState {
                count: 1,
                window_start_ns: now_ns,
            };
            let _ = rate_map.insert(&src_ip, &new_state, 0);
            false
        }
    }
}

/// Check for UDP port-specific rate limiting.
/// Some ports (e.g., DNS 53, NTP 123) have tighter thresholds
/// because they are common amplification vectors.
#[inline(always)]
pub fn get_port_threshold(dst_port: u16, default_threshold: u64) -> u64 {
    match dst_port {
        53 => default_threshold / 4,       // DNS: 4x stricter
        123 => default_threshold / 5,      // NTP: 5x stricter
        161 | 162 => default_threshold / 3, // SNMP: 3x stricter
        389 => default_threshold / 5,      // LDAP: 5x stricter
        1900 => default_threshold / 5,     // SSDP: 5x stricter
        11211 => default_threshold / 10,   // Memcached: 10x stricter
        _ => default_threshold,
    }
}

/// Check if a UDP packet is a potential amplification response.
/// Large inbound UDP packets on common amplification ports
/// are highly suspicious.
#[inline(always)]
pub fn is_amplification_suspect(src_port: u16, payload_len: u16) -> bool {
    match src_port {
        53 if payload_len > 512 => true,    // DNS amp (resp > 512 bytes)
        123 if payload_len > 100 => true,   // NTP monlist
        161 if payload_len > 200 => true,   // SNMP bulk
        389 if payload_len > 200 => true,   // CLDAP
        1900 if payload_len > 200 => true,  // SSDP
        11211 if payload_len > 100 => true, // Memcached
        _ => false,
    }
}
