//! XDP SYNPROXY — Stateless TCP SYN Cookie Defense
//!
//! Implements SYN cookie SYNPROXY at the XDP layer.
//! In passive mode: SYN packets pass to kernel. In active mode (flood detected):
//! XDP intercepts SYNs, generates cookie SYN-ACKs, and bounces via XDP_TX.

use aegis_common::*;
use aya_ebpf::{maps::PerCpuArray, programs::XdpContext};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr};

/// Standard MSS values for SYN cookie encoding.
const MSS_TABLE: [u16; 8] = [536, 1200, 1400, 1440, 1452, 1460, 4312, 8960];

/// Compute a simple hash for SYN cookie generation (FNV-1a inspired).
#[inline(always)]
pub fn compute_cookie_hash(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    secret: u32,
) -> u32 {
    let mut hash: u32 = 2166136261;
    hash ^= src_ip;
    hash = hash.wrapping_mul(16777619);
    hash ^= dst_ip;
    hash = hash.wrapping_mul(16777619);
    hash ^= (src_port as u32) << 16 | (dst_port as u32);
    hash = hash.wrapping_mul(16777619);
    hash ^= secret;
    hash = hash.wrapping_mul(16777619);
    hash
}

/// Encode a SYN cookie into a TCP sequence number.
#[inline(always)]
pub fn encode_syn_cookie(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    mss: u16,
    secret: u32,
) -> u32 {
    let hash = compute_cookie_hash(src_ip, dst_ip, src_port, dst_port, secret);
    let mss_idx = find_mss_index(mss);
    (hash & 0xFFFFFF00) | ((mss_idx as u32) & 0x07)
}

/// Validate a SYN cookie from an incoming ACK.
#[inline(always)]
pub fn validate_syn_cookie(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    ack_num: u32,
    secret: u32,
) -> bool {
    let cookie = ack_num.wrapping_sub(1);
    let expected_hash = compute_cookie_hash(src_ip, dst_ip, src_port, dst_port, secret);
    (cookie & 0xFFFFFF00) == (expected_hash & 0xFFFFFF00)
}

/// Find the closest MSS index for the given MSS value.
#[inline(always)]
fn find_mss_index(mss: u16) -> u8 {
    let mut best_idx: u8 = 5;
    let mut i = 0u8;
    while (i as usize) < MSS_TABLE.len() {
        if MSS_TABLE[i as usize] <= mss {
            best_idx = i;
        }
        i += 1;
    }
    best_idx
}

/// Retrieve the MSS value from a cookie's MSS index.
#[inline(always)]
pub fn get_mss_from_cookie(cookie: u32) -> u16 {
    let idx = (cookie & 0x07) as usize;
    if idx < MSS_TABLE.len() {
        MSS_TABLE[idx]
    } else {
        1460
    }
}

/// Extract the MSS option from TCP options in the SYN packet.
#[inline(always)]
pub fn extract_mss_from_tcp_options(ctx: &XdpContext, tcp_offset: usize) -> u16 {
    let data_start = ctx.data();
    let data_end = ctx.data_end();

    if data_start + tcp_offset + 20 > data_end {
        return 1460;
    }

    let _tcp_hdr = (data_start + tcp_offset) as *const TcpHdr;

    let data_offset_byte = unsafe { *((data_start + tcp_offset + 12) as *const u8) };
    let data_offset = ((data_offset_byte >> 4) as usize) * 4;

    if data_offset <= 20 {
        return 1460;
    }

    let options_start = tcp_offset + 20;
    let options_end = tcp_offset + data_offset;

    if data_start + options_end > data_end {
        return 1460;
    }

    let mut offset = options_start;
    while offset + 1 < options_end {
        if data_start + offset >= data_end {
            break;
        }
        let kind = unsafe { *((data_start + offset) as *const u8) };

        match kind {
            0 => break,
            1 => offset += 1,
            2 => {
                if offset + 4 <= options_end && data_start + offset + 4 <= data_end {
                    let mss_bytes = unsafe {
                        let ptr = (data_start + offset + 2) as *const [u8; 2];
                        *ptr
                    };
                    return u16::from_be_bytes(mss_bytes);
                }
                break;
            }
            _ => {
                if data_start + offset + 1 >= data_end {
                    break;
                }
                let len = unsafe { *((data_start + offset + 1) as *const u8) } as usize;
                if len < 2 {
                    break;
                }
                offset += len;
            }
        }
    }

    1460
}

/// Check if the global SYN rate indicates a flood is in progress.
#[inline(always)]
pub fn check_syn_flood(syn_counter: &PerCpuArray<u64>, threshold: u64, now_ns: u64) -> bool {
    let count = match syn_counter.get(0) {
        Some(c) => *c,
        None => return false,
    };

    let window_start = match syn_counter.get(1) {
        Some(ts) => *ts,
        None => return false,
    };

    let elapsed = now_ns.saturating_sub(window_start);

    if elapsed > RATE_WINDOW_NS {
        if let Some(c) = syn_counter.get_ptr_mut(0) {
            unsafe { *c = 1 };
        }
        if let Some(ts) = syn_counter.get_ptr_mut(1) {
            unsafe { *ts = now_ns };
        }
        false
    } else {
        if let Some(c) = syn_counter.get_ptr_mut(0) {
            unsafe { *c += 1 };
        }
        count >= threshold
    }
}

/// Swap Ethernet MAC addresses in-place for XDP_TX.
#[inline(always)]
pub fn swap_eth_addrs(eth_hdr: *mut EthHdr) {
    unsafe {
        let src = (*eth_hdr).src_addr;
        (*eth_hdr).src_addr = (*eth_hdr).dst_addr;
        (*eth_hdr).dst_addr = src;
    }
}

/// Swap IP addresses in-place for SYN-ACK response.
#[inline(always)]
pub fn swap_ip_addrs(ip_hdr: *mut Ipv4Hdr) {
    unsafe {
        let src = (*ip_hdr).src_addr;
        (*ip_hdr).src_addr = (*ip_hdr).dst_addr;
        (*ip_hdr).dst_addr = src;
    }
}

/// Compute the ones-complement checksum update (RFC 1624).
#[inline(always)]
pub fn csum_update(old_csum: u16, old_val: u16, new_val: u16) -> u16 {
    let mut sum: u32 = (!old_csum as u32) & 0xFFFF;
    sum += (!old_val as u32) & 0xFFFF;
    sum += new_val as u32;
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}
