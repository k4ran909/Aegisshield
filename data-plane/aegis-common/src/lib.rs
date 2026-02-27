//! AegisShield Shared Types — Common definitions for kernel ↔ userspace
//!
//! This crate contains types shared between the eBPF (kernel) and
//! userspace components. All types must be:
//! - `#[repr(C)]` for stable memory layout
//! - `Copy + Clone` for BPF map compatibility
//! - No heap allocations (no_std compatible)

#![no_std]

// ═══════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════

/// Maximum number of entries in the IP blocklist BPF HashMap.
pub const BLOCKLIST_SIZE: u32 = 65536;

/// Maximum number of ACL rules in the Edge Network Firewall.
pub const MAX_ACL_RULES: u32 = 128;

/// Maximum entries in per-IP rate tracking maps (LRU).
pub const RATE_MAP_SIZE: u32 = 131072; // 128K entries

/// Maximum entries in connection tracking map (LRU).
pub const CONNTRACK_SIZE: u32 = 262144; // 256K entries

/// Rate limiting time window in nanoseconds (1 second).
pub const RATE_WINDOW_NS: u64 = 1_000_000_000;

/// Number of per-CPU statistics counters.
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
/// Stored at index 0 of a BPF Array.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct GlobalConfig {
    /// UDP packets-per-second threshold per source IP.
    pub udp_rate_threshold: u64,
    /// Global SYN packets-per-second threshold before activating SYNPROXY.
    pub syn_flood_threshold: u64,
    /// ICMP echo requests-per-second threshold per source IP.
    pub icmp_rate_threshold: u64,
    /// Maximum allowed DNS response size before dropping (anti-amplification).
    pub dns_max_response_size: u16,
    /// Whether fragment filtering is enabled (1=drop all, 2=selective, 0=off).
    pub fragment_policy: u8,
    /// Whether connection tracking bypass is enabled.
    pub conntrack_enabled: u8,
    /// SYN cookie secret (rotated periodically by userspace).
    pub syn_cookie_secret: u32,
    /// Padding for alignment.
    pub _pad: [u8; 4],
}

/// Edge Network Firewall ACL rule.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct AclRule {
    /// Rule priority (lower = higher priority). Index in the BPF Array.
    pub priority: u32,
    /// IP protocol to match (6=TCP, 17=UDP, 1=ICMP, 0=any).
    pub protocol: u8,
    /// Whether this rule is active.
    pub enabled: u8,
    /// Destination port to match (0 = wildcard).
    pub dst_port: u16,
    /// Source port to match (0 = wildcard).
    pub src_port: u16,
    /// Action: 0 = DROP, 1 = PASS.
    pub action: u8,
    /// Direction: 0 = inbound, 1 = outbound, 2 = both.
    pub direction: u8,
}

/// Per-CPU statistics counter value.
/// Each counter is a simple u64 incremented atomically per CPU.
/// Userspace sums across CPUs for the aggregate value.
pub type StatsCounter = u64;

// ═══════════════════════════════════════════════════════════════════
// Stat Name Helpers (for userspace display)
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
