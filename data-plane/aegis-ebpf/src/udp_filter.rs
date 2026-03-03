//! UDP Flood Filter — Per-Source-IP Rate Limiting
//!
//! Uses a BPF LRU HashMap to track per-source-IP packet rates.
//! When the rate exceeds the configured threshold within the
//! time window, all subsequent UDP packets from that IP are dropped.
//!
//! The LRU map automatically evicts the oldest entry when full,
//! ensuring memory usage stays bounded even under heavy attack.

use aegis_common::*;
use aya_ebpf::maps::LruHashMap;

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
/// Amplification vectors and game servers have much tighter thresholds.
#[inline(always)]
pub fn get_port_threshold(dst_port: u16, default_threshold: u64) -> u64 {
    match dst_port {
        // ── Amplification vectors (extremely strict) ──────────────
        53 => default_threshold / 4,        // DNS amplification
        19 => default_threshold / 10,       // Chargen amplification
        69 => default_threshold / 5,        // TFTP amplification
        111 => default_threshold / 5,       // RPC portmap amplification
        123 => default_threshold / 5,       // NTP monlist amplification
        137 | 138 => default_threshold / 5, // NetBIOS amplification
        161 | 162 => default_threshold / 3, // SNMP amplification
        389 => default_threshold / 5,       // CLDAP amplification
        520 => default_threshold / 5,       // RIP amplification
        1900 => default_threshold / 5,      // SSDP amplification
        3283 => default_threshold / 5,      // ARD (Apple Remote Desktop)
        3389 => default_threshold / 5,      // RDP amplification
        3702 => default_threshold / 5,      // WS-Discovery amplification
        5353 => default_threshold / 5,      // mDNS amplification
        5683 => default_threshold / 5,      // CoAP amplification
        11211 => default_threshold / 10,    // Memcached (worst amplifier)
        // ── Game server protocols ─────────────────────────────────
        9987 => default_threshold / 3,  // TeamSpeak 3
        19132 => default_threshold / 3, // Minecraft PE (Bedrock)
        25565 => default_threshold / 3, // Minecraft Java (UDP query)
        27015 => default_threshold / 3, // Valve Source Engine
        30120 => default_threshold / 3, // FiveM
        _ => default_threshold,
    }
}

/// Check if a UDP packet is a potential amplification response.
/// Large inbound UDP packets from common amplification source ports
/// are highly suspicious and dropped immediately.
#[inline(always)]
pub fn is_amplification_suspect(src_port: u16, payload_len: u16) -> bool {
    match src_port {
        // ── Classic amplification reflectors ──────────────────────
        19 if payload_len > 50 => true,   // Chargen (huge amp factor)
        53 if payload_len > 512 => true,  // DNS amplification
        69 if payload_len > 200 => true,  // TFTP amplification
        111 if payload_len > 100 => true, // RPC portmap
        123 if payload_len > 100 => true, // NTP monlist
        137 if payload_len > 100 => true, // NetBIOS
        161 if payload_len > 200 => true, // SNMP bulk
        389 if payload_len > 200 => true, // CLDAP
        520 if payload_len > 100 => true, // RIP
        1900 if payload_len > 200 => true, // SSDP
        3283 if payload_len > 100 => true, // Apple Remote Desktop
        3389 if payload_len > 100 => true, // RDP
        3702 if payload_len > 200 => true, // WS-Discovery
        5353 if payload_len > 200 => true, // mDNS
        5683 if payload_len > 100 => true, // CoAP
        11211 if payload_len > 100 => true, // Memcached (worst: 51000x)
        _ => false,
    }
}
