//! AegisShield XDP Data Plane — Main Entry Point (Refactored)
//!
//! This is the core XDP program that processes every packet at wire speed.
//! It chains all filter modules in a fixed priority order:
//!
//! 1. IP Blocklist         (instant DROP for known-bad IPs)
//! 2. Fragment Filter      (drop fragmented packets)
//! 3. Connection Tracking  (bypass filters for established connections)
//! 4. ACL Engine           (Edge Network Firewall rules)
//! 5. Protocol Filters     (SYN proxy, UDP rate limit, DNS amp, ICMP, GRE)
//! 6. Stats Collection     (per-CPU counters for all decisions)
//!
//! If a packet passes all filters, it is XDP_PASS'd to the kernel stack.

#![no_std]
#![no_main]

mod acl;
mod syn_proxy;
mod udp_filter;
mod dns_filter;
mod icmp_filter;
mod gre_filter;
mod fragment_filter;
mod conntrack;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, HashMap, LruHashMap, PerCpuArray},
    programs::XdpContext,
    helpers::bpf_ktime_get_ns,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};
use aegis_common::*;

// ═══════════════════════════════════════════════════════════════════
// BPF Maps — Shared between kernel and userspace
// ═══════════════════════════════════════════════════════════════════

/// IP Blocklist — HashMap of blocked IP addresses.
/// Key: IPv4 address (u32), Value: block expiry timestamp (u64)
#[map]
static BLOCKLIST: HashMap<u32, u64> = HashMap::with_max_entries(BLOCKLIST_SIZE, 0);

/// Global configuration — thresholds and feature flags.
#[map]
static CONFIG: Array<GlobalConfig> = Array::with_max_entries(1, 0);

/// Edge Network Firewall ACL rules (priority-ordered array).
#[map]
static ACL_RULES: Array<AclRule> = Array::with_max_entries(MAX_ACL_RULES, 0);

/// Per-source UDP rate tracking (LRU for auto-eviction).
#[map]
static UDP_RATE: LruHashMap<u32, udp_filter::UdpRateState> =
    LruHashMap::with_max_entries(RATE_MAP_SIZE, 0);

/// Per-source ICMP rate tracking.
#[map]
static ICMP_RATE: LruHashMap<u32, icmp_filter::IcmpRateState> =
    LruHashMap::with_max_entries(RATE_MAP_SIZE, 0);

/// Per-source GRE rate tracking.
#[map]
static GRE_RATE: LruHashMap<u32, gre_filter::GreRateState> =
    LruHashMap::with_max_entries(RATE_MAP_SIZE / 4, 0);

/// GRE tunnel endpoint whitelist.
#[map]
static GRE_WHITELIST: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

/// DNS outbound query tracker (TxID → timestamp).
#[map]
static DNS_QUERIES: LruHashMap<u16, u64> =
    LruHashMap::with_max_entries(16384, 0);

/// SYN flood rate counter (per-CPU for lock-free tracking).
/// Index 0: count, Index 1: window start timestamp.
#[map]
static SYN_COUNTER: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);

/// Connection tracking table (5-tuple LRU).
#[map]
static CONNTRACK: LruHashMap<conntrack::ConnTrackKey, conntrack::ConnTrackValue> =
    LruHashMap::with_max_entries(CONNTRACK_SIZE, 0);

/// Per-CPU aggregate statistics.
/// Indices: 0=rx, 1=drop, 2=pass, 3=tx, 4=blocklist_drops,
///          5=acl_drops, 6=udp_drops, 7=syn_drops, 8=icmp_drops,
///          9=dns_drops, 10=gre_drops, 11=frag_drops, 12=conntrack_bypass
#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(16, 0);

// ═══════════════════════════════════════════════════════════════════
// XDP Program Entry Point
// ═══════════════════════════════════════════════════════════════════

#[xdp]
pub fn aegis_xdp(ctx: XdpContext) -> u32 {
    match process_packet(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS, // Parse error — pass to stack
    }
}

/// Main packet processing pipeline.
#[inline(always)]
fn process_packet(ctx: &XdpContext) -> Result<u32, ()> {
    let now_ns = unsafe { bpf_ktime_get_ns() };

    // ── Statistics: count every received packet ─────────────────
    inc_stat(0); // STAT_RX

    // ── Parse Ethernet Header ───────────────────────────────────
    let eth_hdr = ptr_at::<EthHdr>(ctx, 0)?;
    let eth_hdr_ref = unsafe { &*eth_hdr };

    // Only process IPv4 for now (IPv6 support is Phase 2+).
    if eth_hdr_ref.ether_type != EtherType::Ipv4 {
        inc_stat(2); // STAT_PASS
        return Ok(xdp_action::XDP_PASS);
    }

    // ── Parse IPv4 Header ───────────────────────────────────────
    let ip_hdr = ptr_at::<Ipv4Hdr>(ctx, mem::size_of::<EthHdr>())?;
    let ip_hdr_ref = unsafe { &*ip_hdr };

    let src_ip = u32::from_be(ip_hdr_ref.src_addr);
    let dst_ip = u32::from_be(ip_hdr_ref.dst_addr);
    let protocol = ip_hdr_ref.proto;
    let ip_total_len = u16::from_be(ip_hdr_ref.tot_len);
    let frag_flags = ip_hdr_ref.frag_off;

    // ── Stage 1: IP Blocklist ───────────────────────────────────
    if unsafe { BLOCKLIST.get(&src_ip) }.is_some() {
        inc_stat(1); // STAT_DROP
        inc_stat(4); // STAT_BLOCKLIST_DROP
        return Ok(xdp_action::XDP_DROP);
    }

    // ── Stage 2: Fragment Filter ────────────────────────────────
    if fragment_filter::should_drop_fragment(frag_flags, ip_hdr_ref.tot_len) {
        inc_stat(1); // STAT_DROP
        inc_stat(11); // STAT_FRAG_DROP
        return Ok(xdp_action::XDP_DROP);
    }

    // ── Load Configuration ──────────────────────────────────────
    let config = match CONFIG.get(0) {
        Some(c) => unsafe { &*c },
        None => return Ok(xdp_action::XDP_PASS), // No config = pass all
    };

    // ── Parse L4 Headers ────────────────────────────────────────
    let ip_hdr_len = ((unsafe { *((ctx.data() + mem::size_of::<EthHdr>()) as *const u8) } & 0x0F) as usize) * 4;
    let l4_offset = mem::size_of::<EthHdr>() + ip_hdr_len;

    let (src_port, dst_port) = match protocol {
        6 => {
            // TCP
            let tcp_hdr = ptr_at::<TcpHdr>(ctx, l4_offset)?;
            let tcp_ref = unsafe { &*tcp_hdr };
            (u16::from_be(tcp_ref.source), u16::from_be(tcp_ref.dest))
        }
        17 => {
            // UDP
            let udp_hdr = ptr_at::<UdpHdr>(ctx, l4_offset)?;
            let udp_ref = unsafe { &*udp_hdr };
            (u16::from_be(udp_ref.source), u16::from_be(udp_ref.dest))
        }
        _ => (0u16, 0u16),
    };

    // ── Stage 3: Connection Tracking ────────────────────────────
    // If packet belongs to a known connection, bypass flood filters.
    if protocol == 6 || protocol == 17 {
        if conntrack::is_tracked(&CONNTRACK, protocol, src_ip, dst_ip, src_port, dst_port) {
            inc_stat(2);  // STAT_PASS
            inc_stat(12); // STAT_CONNTRACK_BYPASS
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // ── Stage 4: ACL Engine ─────────────────────────────────────
    if let Some(allowed) = acl::evaluate_acl(&ACL_RULES, protocol, src_port, dst_port) {
        if !allowed {
            inc_stat(1); // STAT_DROP
            inc_stat(5); // STAT_ACL_DROP
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // ── Stage 5: Protocol-Specific Filters ──────────────────────
    match protocol {
        6 => {
            // TCP — SYN flood detection
            let tcp_hdr = ptr_at::<TcpHdr>(ctx, l4_offset)?;
            let tcp_ref = unsafe { &*tcp_hdr };
            let flags = unsafe { *((&*tcp_hdr as *const TcpHdr as *const u8).add(13)) };
            let is_syn = (flags & 0x02) != 0 && (flags & 0x10) == 0;

            if is_syn {
                // Check if SYN flood is active.
                let flood_active = syn_proxy::check_syn_flood(
                    &SYN_COUNTER,
                    config.syn_flood_threshold,
                    now_ns,
                );

                if flood_active {
                    inc_stat(1); // STAT_DROP
                    inc_stat(7); // STAT_SYN_DROP
                    // In production: XDP_TX with SYN cookie response.
                    // For now: DROP to protect against flood.
                    return Ok(xdp_action::XDP_DROP);
                }
            }

            // Track the connection for bypass on subsequent packets.
            if conntrack::should_track_tcp(flags) {
                conntrack::track_connection(
                    &CONNTRACK,
                    protocol, src_ip, dst_ip, src_port, dst_port,
                    now_ns, ip_total_len as u64,
                    if is_syn { conntrack::ConnState::New } else { conntrack::ConnState::Established },
                );
            }
        }

        17 => {
            // UDP — Multi-layer filtering
            let udp_hdr = ptr_at::<UdpHdr>(ctx, l4_offset)?;
            let udp_ref = unsafe { &*udp_hdr };
            let udp_payload_len = u16::from_be(udp_ref.len).saturating_sub(8);

            // Check amplification first (source port based).
            if udp_filter::is_amplification_suspect(src_port, udp_payload_len) {
                inc_stat(1); // STAT_DROP
                inc_stat(9); // STAT_DNS_DROP
                return Ok(xdp_action::XDP_DROP);
            }

            // DNS deep inspection (dst_port 53 or src_port 53).
            if src_port == 53 || dst_port == 53 {
                let dns_offset = l4_offset + mem::size_of::<UdpHdr>();
                if ctx.data() + dns_offset + mem::size_of::<dns_filter::DnsHeader>() <= ctx.data_end() {
                    let dns_hdr = unsafe {
                        &*((ctx.data() + dns_offset) as *const dns_filter::DnsHeader)
                    };

                    if dns_filter::check_dns_amplification(
                        dns_hdr,
                        udp_payload_len,
                        src_ip,
                        config.dns_max_response_size,
                        &DNS_QUERIES,
                    ) {
                        inc_stat(1); // STAT_DROP
                        inc_stat(9); // STAT_DNS_DROP
                        return Ok(xdp_action::XDP_DROP);
                    }
                }
            }

            // Per-IP UDP rate limiting with port-specific thresholds.
            let threshold = udp_filter::get_port_threshold(
                dst_port,
                config.udp_rate_threshold,
            );

            if udp_filter::check_udp_rate(&UDP_RATE, src_ip, threshold, now_ns) {
                inc_stat(1); // STAT_DROP
                inc_stat(6); // STAT_UDP_DROP
                return Ok(xdp_action::XDP_DROP);
            }
        }

        1 => {
            // ICMP
            if ctx.data() + l4_offset + 2 <= ctx.data_end() {
                let icmp_type = unsafe { *((ctx.data() + l4_offset) as *const u8) };
                let icmp_code = unsafe { *((ctx.data() + l4_offset + 1) as *const u8) };
                let icmp_payload_len = ip_total_len.saturating_sub((ip_hdr_len + 8) as u16);

                match icmp_filter::check_icmp(
                    &ICMP_RATE,
                    src_ip,
                    icmp_type,
                    icmp_code,
                    icmp_payload_len,
                    config.icmp_rate_threshold,
                    now_ns,
                ) {
                    icmp_filter::IcmpAction::Drop => {
                        inc_stat(1); // STAT_DROP
                        inc_stat(8); // STAT_ICMP_DROP
                        return Ok(xdp_action::XDP_DROP);
                    }
                    icmp_filter::IcmpAction::Pass => {}
                }
            }
        }

        47 => {
            // GRE (Protocol 47)
            if ctx.data() + l4_offset + mem::size_of::<gre_filter::GreHeader>() <= ctx.data_end() {
                let gre_hdr = unsafe {
                    &*((ctx.data() + l4_offset) as *const gre_filter::GreHeader)
                };

                // GRE rate is 1/10th of UDP threshold by default.
                let gre_threshold = config.udp_rate_threshold / 10;
                if gre_filter::check_gre(
                    &GRE_RATE,
                    &GRE_WHITELIST,
                    src_ip,
                    gre_hdr,
                    gre_threshold,
                    now_ns,
                ) {
                    inc_stat(1);  // STAT_DROP
                    inc_stat(10); // STAT_GRE_DROP
                    return Ok(xdp_action::XDP_DROP);
                }
            }
        }

        _ => {
            // Unknown protocol — pass to kernel.
        }
    }

    // ── Packet passed all filters ───────────────────────────────
    inc_stat(2); // STAT_PASS
    Ok(xdp_action::XDP_PASS)
}

// ═══════════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════════

/// Safely cast a pointer at the given offset within the XDP context.
/// Performs bounds checking to satisfy the eBPF verifier.
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

/// Increment a per-CPU statistics counter.
#[inline(always)]
fn inc_stat(index: u32) {
    if let Some(counter) = STATS.get_ptr_mut(index) {
        unsafe { *counter += 1 };
    }
}

/// Panic handler (required for no_std).
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
