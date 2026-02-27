//! Lightweight Connection Tracking in BPF Maps
//!
//! Tracks established TCP/UDP connections to allow reverse traffic
//! without rate limiting. Entries expire via LRU eviction.

use aya_ebpf::maps::LruHashMap;

/// Connection tracking key (5-tuple).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnTrackKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3],
}

/// Connection tracking value.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnTrackValue {
    pub last_seen_ns: u64,
    pub packets: u64,
    pub bytes: u64,
    pub state: u8,
    pub _pad: [u8; 7],
}

/// TCP connection state (simplified for XDP performance).
#[repr(u8)]
#[derive(Copy, Clone, PartialEq)]
pub enum ConnState {
    New = 0,
    Established = 1,
    _TimeWait = 2,
}

/// Check if a packet belongs to a tracked connection.
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

    if unsafe { conntrack.get(&key) }.is_some() {
        return true;
    }

    // Check reverse direction.
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

/// Check if TCP flags warrant creating a conntrack entry.
#[inline(always)]
pub fn should_track_tcp(tcp_flags: u8) -> bool {
    let syn = (tcp_flags & 0x02) != 0;
    let ack = (tcp_flags & 0x10) != 0;
    let rst = (tcp_flags & 0x04) != 0;
    !rst && (syn || ack)
}
