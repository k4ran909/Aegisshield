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

#[map]
static BLOCKLIST: HashMap<u32, u64> = HashMap::with_max_entries(BLOCKLIST_SIZE, 0);

#[map]
static CONFIG: Array<GlobalConfig> = Array::with_max_entries(1, 0);

#[map]
static ACL_RULES: Array<AclRule> = Array::with_max_entries(MAX_ACL_RULES, 0);

#[map]
static UDP_RATE: LruHashMap<u32, udp_filter::UdpRateState> =
    LruHashMap::with_max_entries(RATE_MAP_SIZE, 0);

#[map]
static ICMP_RATE: LruHashMap<u32, icmp_filter::IcmpRateState> =
    LruHashMap::with_max_entries(RATE_MAP_SIZE, 0);

#[map]
static GRE_RATE: LruHashMap<u32, gre_filter::GreRateState> =
    LruHashMap::with_max_entries(RATE_MAP_SIZE / 4, 0);

#[map]
static GRE_WHITELIST: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

#[map]
static SYN_COUNTER: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);

#[map]
static CONNTRACK: LruHashMap<conntrack::ConnTrackKey, conntrack::ConnTrackValue> =
    LruHashMap::with_max_entries(CONNTRACK_SIZE, 0);

#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(16, 0);

#[xdp]
pub fn aegis_xdp(ctx: XdpContext) -> u32 {
    match process_packet(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn process_packet(ctx: &XdpContext) -> Result<u32, ()> {
    let now_ns = unsafe { bpf_ktime_get_ns() };
    inc_stat(STAT_RX);

    let eth_hdr = ptr_at::<EthHdr>(ctx, 0)?;
    let ether_type =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth_hdr).ether_type)) };
    if ether_type != EtherType::Ipv4 {
        inc_stat(STAT_PASS);
        return Ok(xdp_action::XDP_PASS);
    }

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
    let raw_tot_len = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_hdr).tot_len)) };
    let frag_flags = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_hdr).frag_off)) };
    let src_ip_host = u32::from_be(src_ip);
    let dst_ip_host = u32::from_be(dst_ip);

    // ════════════════════════════════════════════════════════════════
    // HARDCODED SSH FAST-PATH — SSH (TCP port 22) is NEVER dropped.
    // This runs BEFORE blocklist, fragment filter, conntrack, ACL,
    // and all rate limiters. Nothing can block SSH.
    // ════════════════════════════════════════════════════════════════
    if matches!(protocol, IpProto::Tcp) {
        // Read actual IP header length (IHL field) — don't assume 20 bytes
        let ihl_byte_ptr = ptr_at::<u8>(ctx, mem::size_of::<EthHdr>())?;
        let ihl_val = ((unsafe { *ihl_byte_ptr } & 0x0F) as usize) * 4;
        let tcp_offset = mem::size_of::<EthHdr>() + ihl_val;
        if let Ok(tcp_peek) = ptr_at::<TcpHdr>(ctx, tcp_offset) {
            let s = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp_peek).source)) };
            let d = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp_peek).dest)) };
            let sp = u16::from_be(s);
            let dp = u16::from_be(d);
            // Pass if EITHER src or dst port is 22 (covers inbound + response)
            if dp == 22 || sp == 22 {
                inc_stat(STAT_PASS);
                return Ok(xdp_action::XDP_PASS);
            }
        }
    }

    if let Some(expiry_ns) = unsafe { BLOCKLIST.get(&src_ip_host) } {
        if *expiry_ns == 0 || now_ns <= *expiry_ns {
            inc_stat(STAT_DROP);
            inc_stat(STAT_BLOCKLIST_DROP);
            return Ok(xdp_action::XDP_DROP);
        }
        let _ = BLOCKLIST.remove(&src_ip_host);
    }

    let config = match CONFIG.get(0) {
        Some(c) => c,
        None => return Ok(xdp_action::XDP_PASS),
    };

    let should_drop_fragment = match config.fragment_policy {
        0 => false,
        2 => fragment_filter::should_drop_fragment_selective(frag_flags, raw_tot_len),
        _ => fragment_filter::should_drop_fragment(frag_flags, raw_tot_len),
    };
    if should_drop_fragment {
        inc_stat(STAT_DROP);
        inc_stat(STAT_FRAG_DROP);
        return Ok(xdp_action::XDP_DROP);
    }

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

    if config.conntrack_enabled != 0 && matches!(protocol, IpProto::Tcp | IpProto::Udp) {
        if conntrack::is_tracked(
            &CONNTRACK,
            proto_u8,
            src_ip_host,
            dst_ip_host,
            src_port,
            dst_port,
        ) {
            inc_stat(STAT_PASS);
            inc_stat(STAT_CONNTRACK_BYPASS);
            return Ok(xdp_action::XDP_PASS);
        }
    }

    if let Some(allowed) = acl::evaluate_acl(&ACL_RULES, proto_u8, src_port, dst_port) {
        if !allowed {
            inc_stat(STAT_DROP);
            inc_stat(STAT_ACL_DROP);
            return Ok(xdp_action::XDP_DROP);
        }
        // ACL explicitly allows this traffic — bypass ALL rate limiting.
        // This ensures SSH, HTTPS, etc. are NEVER dropped by flood filters.
        if config.conntrack_enabled != 0 && matches!(protocol, IpProto::Tcp | IpProto::Udp) {
            conntrack::track_connection(
                &CONNTRACK,
                proto_u8,
                src_ip_host,
                dst_ip_host,
                src_port,
                dst_port,
                now_ns,
                ip_total_len as u64,
                conntrack::ConnState::Established,
            );
        }
        inc_stat(STAT_PASS);
        return Ok(xdp_action::XDP_PASS);
    }

    match protocol {
        IpProto::Tcp => {
            let _tcp_hdr = ptr_at::<TcpHdr>(ctx, l4_offset)?;
            let flags = unsafe { *((ctx.data() + l4_offset + 13) as *const u8) };
            let is_syn = (flags & 0x02) != 0 && (flags & 0x10) == 0;

            if is_syn {
                let flood_active =
                    syn_proxy::check_syn_flood(&SYN_COUNTER, config.syn_flood_threshold, now_ns);
                if flood_active {
                    inc_stat(STAT_DROP);
                    inc_stat(STAT_SYN_DROP);
                    return Ok(xdp_action::XDP_DROP);
                }
            }

            if config.conntrack_enabled != 0 && conntrack::should_track_tcp(flags) {
                conntrack::track_connection(
                    &CONNTRACK,
                    proto_u8,
                    src_ip_host,
                    dst_ip_host,
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
        }

        IpProto::Udp => {
            let udp_hdr = ptr_at::<UdpHdr>(ctx, l4_offset)?;
            let udp_len = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*udp_hdr).len)) };
            let udp_payload_len = u16::from_be(udp_len).saturating_sub(8);

            if udp_filter::is_amplification_suspect(src_port, udp_payload_len) {
                inc_stat(STAT_DROP);
                inc_stat(STAT_DNS_DROP);
                return Ok(xdp_action::XDP_DROP);
            }

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
                        config.dns_max_response_size,
                    ) {
                        inc_stat(STAT_DROP);
                        inc_stat(STAT_DNS_DROP);
                        return Ok(xdp_action::XDP_DROP);
                    }
                }
            }

            let threshold = udp_filter::get_port_threshold(dst_port, config.udp_rate_threshold);
            if udp_filter::check_udp_rate(&UDP_RATE, src_ip_host, threshold, now_ns) {
                inc_stat(STAT_DROP);
                inc_stat(STAT_UDP_DROP);
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
                        inc_stat(STAT_DROP);
                        inc_stat(STAT_ICMP_DROP);
                        return Ok(xdp_action::XDP_DROP);
                    }
                    icmp_filter::IcmpAction::Pass => {}
                }
            }
        }

        _ if proto_u8 == 47 => {
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
                    inc_stat(STAT_DROP);
                    inc_stat(STAT_GRE_DROP);
                    return Ok(xdp_action::XDP_DROP);
                }
            }
        }

        _ => {}
    }

    inc_stat(STAT_PASS);
    Ok(xdp_action::XDP_PASS)
}

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

#[inline(always)]
fn inc_stat(index: u32) {
    if let Some(counter) = STATS.get_ptr_mut(index) {
        unsafe { *counter += 1 };
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
