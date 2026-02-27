//! Lightweight Connection Tracking in BPF Maps
//!
//! Tracks established TCP connections to allow reverse traffic
//! (server → client responses) without rate limiting.
//! This prevents legitimate response traffic from being falsely
//! rate-limited or dropped.
//!
//! Design:
//! - Outbound SYN packets create a conntrack entry.
//! - Inbound packets matching a conntrack entry skip flood filters.
//! - Entries expire via LRU eviction after inactivity.
//! - Only tracks 5-tuple: (protocol, src_ip, dst_ip, src_port, dst_port).

use aya_ebpf::maps::LruHashMap;
use aegis_common::*;

/// Connection tracking key (5-tuple hash).
/// Compact 16-byte key for BPF HashMap.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnTrackKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3], // Align to 4 bytes
}

/// Connection tracking value.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnTrackValue {
    pub last_seen_ns: u64,
    pub packets: u64,
    pub bytes: u64,
    pub state: u8,          // See ConnState below
    pub _pad: [u8; 7],
}

/// TCP connection state (simplified for XDP performance).
#[repr(u8)]
#[derive(Copy, Clone, PartialEq)]
pub enum ConnState {
    New = 0,
    Established = 1,
    TimeWait = 2,
}

/// Check if a packet belongs to an established/known connection.
///
/// Returns `true` if the packet is part of a tracked connection.
#[inline(always)]
pub fn is_tracked(
    conntrack: &LruHashMap<ConnTrackKey, ConnTrackValue>,
    protocol: u8,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
) -> bool {
    let key = ConnTrackKey {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        _pad: [0u8; 3],
    };

    // Check forward direction.
    if unsafe { conntrack.get(&key) }.is_some() {
        return true;
    }

    // Check reverse direction (response to our outbound traffic).
    let rev_key = ConnTrackKey {
        src_ip: dst_ip,
        dst_ip: src_ip,
        src_port: dst_port,
        dst_port: src_port,
        protocol,
        _pad: [0u8; 3],
    };

    unsafe { conntrack.get(&rev_key) }.is_some()
}

/// Create or update a connection tracking entry.
#[inline(always)]
pub fn track_connection(
    conntrack: &LruHashMap<ConnTrackKey, ConnTrackValue>,
    protocol: u8,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    now_ns: u64,
    pkt_len: u64,
    state: ConnState,
) {
    let key = ConnTrackKey {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        _pad: [0u8; 3],
    };

    match unsafe { conntrack.get(&key) } {
        Some(existing) => {
            // Update existing entry.
            let new_val = ConnTrackValue {
                last_seen_ns: now_ns,
                packets: existing.packets + 1,
                bytes: existing.bytes + pkt_len,
                state: state as u8,
                _pad: [0u8; 7],
            };
            let _ = conntrack.insert(&key, &new_val, 0);
        }
        None => {
            // Create new entry.
            let val = ConnTrackValue {
                last_seen_ns: now_ns,
                packets: 1,
                bytes: pkt_len,
                state: state as u8,
                _pad: [0u8; 7],
            };
            let _ = conntrack.insert(&key, &val, 0);
        }
    }
}

/// Check if a TCB SYN+ACK should create a conntrack entry.
/// Only track when we see a SYN going out or an established ACK.
#[inline(always)]
pub fn should_track_tcp(tcp_flags: u8) -> bool {
    let syn = (tcp_flags & 0x02) != 0;
    let ack = (tcp_flags & 0x10) != 0;
    let rst = (tcp_flags & 0x04) != 0;

    // Track: SYN (new outbound), SYN+ACK (new inbound), ACK (data)
    // Don't track: RST (connection closing)
    !rst && (syn || ack)
}
