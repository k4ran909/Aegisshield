//! AegisShield Shared Types — Common definitions for kernel ↔ userspace
//!
//! All types must be `#[repr(C)]`, `Copy + Clone`, and no_std compatible.

#![no_std]

// ═══════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════

pub const BLOCKLIST_SIZE: u32 = 65536;
pub const MAX_ACL_RULES: u32 = 128;
pub const RATE_MAP_SIZE: u32 = 131072;
pub const CONNTRACK_SIZE: u32 = 262144;
pub const RATE_WINDOW_NS: u64 = 1_000_000_000;
pub const NUM_STATS: u32 = 16;

// ─── Statistics Indices ─────────────────────────────────────────
pub const STAT_RX: u32 = 0;
pub const STAT_DROP: u32 = 1;
pub const STAT_PASS: u32 = 2;
pub const STAT_TX: u32 = 3;
pub const STAT_BLOCKLIST_DROP: u32 = 4;
pub const STAT_ACL_DROP: u32 = 5;
pub const STAT_UDP_DROP: u32 = 6;
pub const STAT_SYN_DROP: u32 = 7;
pub const STAT_ICMP_DROP: u32 = 8;
pub const STAT_DNS_DROP: u32 = 9;
pub const STAT_GRE_DROP: u32 = 10;
pub const STAT_FRAG_DROP: u32 = 11;
pub const STAT_CONNTRACK_BYPASS: u32 = 12;
pub const STAT_SYN_COOKIES_SENT: u32 = 13;

// ═══════════════════════════════════════════════════════════════════
// BPF Map Value Types
// ═══════════════════════════════════════════════════════════════════

/// Global configuration pushed from userspace to the XDP CONFIG map.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct GlobalConfig {
    pub udp_rate_threshold: u64,
    pub syn_flood_threshold: u64,
    pub icmp_rate_threshold: u64,
    pub dns_max_response_size: u16,
    pub fragment_policy: u8,
    pub conntrack_enabled: u8,
    pub syn_cookie_secret: u32,
    pub _pad: [u8; 4],
}

// Safety: GlobalConfig is #[repr(C)], Copy, and all fields are plain data types.
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for GlobalConfig {}

/// Edge Network Firewall ACL rule.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct AclRule {
    pub priority: u32,
    pub protocol: u8,
    pub enabled: u8,
    pub dst_port: u16,
    pub src_port: u16,
    pub action: u8,
    pub direction: u8,
}

// Safety: AclRule is #[repr(C)], Copy, and all fields are plain data types.
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for AclRule {}

/// Per-CPU statistics counter value.
pub type StatsCounter = u64;

// ═══════════════════════════════════════════════════════════════════
// Stat Name Helpers
// ═══════════════════════════════════════════════════════════════════

/// Get the human-readable name for a statistics index.
pub fn stat_name(index: u32) -> &'static str {
    match index {
        STAT_RX => "rx_packets",
        STAT_DROP => "dropped_total",
        STAT_PASS => "passed_total",
        STAT_TX => "tx_packets",
        STAT_BLOCKLIST_DROP => "blocklist_drops",
        STAT_ACL_DROP => "acl_drops",
        STAT_UDP_DROP => "udp_rate_drops",
        STAT_SYN_DROP => "syn_flood_drops",
        STAT_ICMP_DROP => "icmp_rate_drops",
        STAT_DNS_DROP => "dns_amp_drops",
        STAT_GRE_DROP => "gre_flood_drops",
        STAT_FRAG_DROP => "fragment_drops",
        STAT_CONNTRACK_BYPASS => "conntrack_bypass",
        STAT_SYN_COOKIES_SENT => "syn_cookies_sent",
        _ => "unknown",
    }
}
