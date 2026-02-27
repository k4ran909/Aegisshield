//! AegisShield XDP Data Plane — Main Entry Point
//!
//! Core XDP program that processes every packet at wire speed.
//! Pipeline stages:
//!   1. IP Blocklist → 2. Fragment Filter → 3. Connection Tracking
//!   4. ACL Engine → 5. Protocol Filters → 6. Stats Collection

#![no_std]
#![no_main]
#![allow(dead_code)]

mod acl;
mod conntrack;
mod dns_filter;
mod fragment_filter;
mod gre_filter;
mod icmp_filter;
mod syn_proxy;
mod udp_filter;

use aegis_common::*;
use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{Array, HashMap, LruHashMap, PerCpuArray},
    programs::XdpContext,
};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// ═══════════════════════════════════════════════════════════════════
// BPF Maps — Shared between kernel and userspace
// ═══════════════════════════════════════════════════════════════════

/// IP Blocklist — blocked IP addresses with expiry timestamps.
#[map]
static BLOCKLIST: HashMap<u32, u64> = HashMap::with_max_entries(BLOCKLIST_SIZE, 0);

/// Global configuration — thresholds and feature flags.
#[map]
static CONFIG: Array<GlobalConfig> = Array::with_max_entries(1, 0);

/// Edge Network Firewall ACL rules (priority-ordered).
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
static DNS_QUERIES: LruHashMap<u16, u64> = LruHashMap::with_max_entries(16384, 0);

/// SYN flood rate counter (per-CPU for lock-free tracking).
#[map]
static SYN_COUNTER: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);

/// Connection tracking table (5-tuple LRU).
#[map]
static CONNTRACK: LruHashMap<conntrack::ConnTrackKey, conntrack::ConnTrackValue> =
    LruHashMap::with_max_entries(CONNTRACK_SIZE, 0);

/// Per-CPU aggregate statistics (16 counters).
#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(16, 0);

// ═══════════════════════════════════════════════════════════════════
// XDP Program Entry Point
// ═══════════════════════════════════════════════════════════════════

#[xdp]
pub fn aegis_xdp(ctx: XdpContext) -> u32 {
    match process_packet(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
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
    // EthHdr is packed (1-byte aligned); use addr_of! + read_unaligned.
    let ether_type =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth_hdr).ether_type)) };
    if ether_type != EtherType::Ipv4 {
        inc_stat(2); // STAT_PASS
        return Ok(xdp_action::XDP_PASS);
    }

    // ── Parse IPv4 Header ───────────────────────────────────────
    let ip_hdr = ptr_at::<Ipv4Hdr>(ctx, mem::size_of::<EthHdr>())?;
    let src_ip = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_hdr).src_addr)) };
    let dst_ip = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_hdr).dst_addr)) };
    let protocol = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_hdr).proto)) };
    let proto_u8 = protocol as u8;
    let ip_total_len = unsafe {
        u16::from_be(core::ptr::read_unaligned(core::ptr::addr_of!(
            (*ip_hdr).tot_len
        )))
    };
    let frag_flags = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_hdr).frag_off)) };
    let src_ip_host = u32::from_be(src_ip);
    let _dst_ip_host = u32::from_be(dst_ip);

    // ── Stage 1: IP Blocklist ───────────────────────────────────
    if unsafe { BLOCKLIST.get(&src_ip_host) }.is_some() {
        inc_stat(1); // STAT_DROP
        inc_stat(4); // STAT_BLOCKLIST_DROP
        return Ok(xdp_action::XDP_DROP);
    }

    // ── Stage 2: Fragment Filter ────────────────────────────────
    let raw_tot_len = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_hdr).tot_len)) };
    if fragment_filter::should_drop_fragment(frag_flags, raw_tot_len) {
        inc_stat(1); // STAT_DROP
        inc_stat(11); // STAT_FRAG_DROP
        return Ok(xdp_action::XDP_DROP);
    }

    // ── Load Configuration ──────────────────────────────────────
    let config = match CONFIG.get(0) {
        Some(c) => c,
        None => return Ok(xdp_action::XDP_PASS),
    };

    // ── Parse L4 Headers ────────────────────────────────────────
    let ihl_ptr = ptr_at::<u8>(ctx, mem::size_of::<EthHdr>())?;
    let ihl_byte = unsafe { *ihl_ptr };
    let ip_hdr_len = ((ihl_byte & 0x0F) as usize) * 4;
    let l4_offset = mem::size_of::<EthHdr>() + ip_hdr_len;

    let (src_port, dst_port) = match protocol {
        IpProto::Tcp => {
            let tcp_hdr = ptr_at::<TcpHdr>(ctx, l4_offset)?;
            let src = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp_hdr).source)) };
            let dst = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp_hdr).dest)) };
            (u16::from_be(src), u16::from_be(dst))
        }
        IpProto::Udp => {
            let udp_hdr = ptr_at::<UdpHdr>(ctx, l4_offset)?;
            let src = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*udp_hdr).source)) };
            let dst = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*udp_hdr).dest)) };
            (u16::from_be(src), u16::from_be(dst))
        }
        _ => (0u16, 0u16),
    };

    // ── Stage 3: Connection Tracking ────────────────────────────
    if matches!(protocol, IpProto::Tcp | IpProto::Udp) {
        if conntrack::is_tracked(
            &CONNTRACK,
            proto_u8,
            src_ip_host,
            _dst_ip_host,
            src_port,
            dst_port,
        ) {
            inc_stat(2); // STAT_PASS
            inc_stat(12); // STAT_CONNTRACK_BYPASS
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // ── Stage 4: ACL Engine ─────────────────────────────────────
    if let Some(allowed) = acl::evaluate_acl(&ACL_RULES, proto_u8, src_port, dst_port) {
        if !allowed {
            inc_stat(1); // STAT_DROP
            inc_stat(5); // STAT_ACL_DROP
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // ── Stage 5: Protocol-Specific Filters ──────────────────────
    match protocol {
        IpProto::Tcp => {
            // TCP — SYN flood detection
            let tcp_hdr = ptr_at::<TcpHdr>(ctx, l4_offset)?;
            let flags = unsafe { *((ctx.data() + l4_offset + 13) as *const u8) };
            let is_syn = (flags & 0x02) != 0 && (flags & 0x10) == 0;

            if is_syn {
                let flood_active =
                    syn_proxy::check_syn_flood(&SYN_COUNTER, config.syn_flood_threshold, now_ns);

                if flood_active {
                    inc_stat(1); // STAT_DROP
                    inc_stat(7); // STAT_SYN_DROP
                    return Ok(xdp_action::XDP_DROP);
                }
            }

            // Track the connection for bypass on subsequent packets.
            if conntrack::should_track_tcp(flags) {
                conntrack::track_connection(
                    &CONNTRACK,
                    proto_u8,
                    src_ip_host,
                    _dst_ip_host,
                    src_port,
                    dst_port,
                    now_ns,
                    ip_total_len as u64,
                    if is_syn {
                        conntrack::ConnState::New
                    } else {
                        conntrack::ConnState::Established
                    },
                );
            }

            // Suppress unused variable warning for tcp_hdr (used for bounds check).
            let _ = tcp_hdr;
        }

        IpProto::Udp => {
            // UDP — Multi-layer filtering
            let udp_hdr = ptr_at::<UdpHdr>(ctx, l4_offset)?;
            let udp_len = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*udp_hdr).len)) };
            let udp_payload_len = u16::from_be(udp_len).saturating_sub(8);

            // Check amplification first (source port based).
            if udp_filter::is_amplification_suspect(src_port, udp_payload_len) {
                inc_stat(1); // STAT_DROP
                inc_stat(9); // STAT_DNS_DROP
                return Ok(xdp_action::XDP_DROP);
            }

            // DNS deep inspection (dst_port 53 or src_port 53).
            if src_port == 53 || dst_port == 53 {
                let dns_offset = l4_offset + mem::size_of::<UdpHdr>();
                if ctx.data() + dns_offset + mem::size_of::<dns_filter::DnsHeader>()
                    <= ctx.data_end()
                {
                    let dns_hdr =
                        unsafe { &*((ctx.data() + dns_offset) as *const dns_filter::DnsHeader) };

                    if dns_filter::check_dns_amplification(
                        dns_hdr,
                        udp_payload_len,
                        src_ip_host,
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
            let threshold = udp_filter::get_port_threshold(dst_port, config.udp_rate_threshold);

            if udp_filter::check_udp_rate(&UDP_RATE, src_ip_host, threshold, now_ns) {
                inc_stat(1); // STAT_DROP
                inc_stat(6); // STAT_UDP_DROP
                return Ok(xdp_action::XDP_DROP);
            }
        }

        IpProto::Icmp => {
            if ctx.data() + l4_offset + 2 <= ctx.data_end() {
                let icmp_type = unsafe { *((ctx.data() + l4_offset) as *const u8) };
                let icmp_code = unsafe { *((ctx.data() + l4_offset + 1) as *const u8) };
                let icmp_payload_len = ip_total_len.saturating_sub((ip_hdr_len + 8) as u16);

                match icmp_filter::check_icmp(
                    &ICMP_RATE,
                    src_ip_host,
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

        _ if proto_u8 == 47 => {
            // GRE (Protocol 47)
            if ctx.data() + l4_offset + mem::size_of::<gre_filter::GreHeader>() <= ctx.data_end() {
                let gre_hdr =
                    unsafe { &*((ctx.data() + l4_offset) as *const gre_filter::GreHeader) };

                let gre_threshold = config.udp_rate_threshold / 10;
                if gre_filter::check_gre(
                    &GRE_RATE,
                    &GRE_WHITELIST,
                    src_ip_host,
                    gre_hdr,
                    gre_threshold,
                    now_ns,
                ) {
                    inc_stat(1); // STAT_DROP
                    inc_stat(10); // STAT_GRE_DROP
                    return Ok(xdp_action::XDP_DROP);
                }
            }
        }

        _ => {}
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
