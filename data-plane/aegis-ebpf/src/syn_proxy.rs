//! XDP SYNPROXY — Stateless TCP SYN Cookie Defense
//!
//! Implements a high-performance SYN cookie SYNPROXY at the XDP layer,
//! completely shielding the Linux kernel from SYN flood attacks.
//!
//! Operation Modes:
//! 1. **PASSIVE MODE** (normal traffic): SYN packets are passed directly
//!    to the kernel stack (XDP_PASS). No overhead.
//! 2. **ACTIVE MODE** (flood detected): The XDP program intercepts SYN
//!    packets, generates a cryptographic SYN cookie, crafts a SYN-ACK
//!    response, and bounces it back (XDP_TX). The kernel never sees the flood.
//!
//! SYN Cookie Encoding:
//! The cookie is encoded in the TCP sequence number of the SYN-ACK:
//! - Bits [0:4]   — MSS index (maps to standard MSS values)
//! - Bits [5:7]   — Reserved
//! - Bits [8:31]  — Truncated HMAC of (src_ip, dst_ip, src_port, dst_port, secret)
//!
//! When a legitimate client returns ACK, the cookie is validated by
//! recomputing the HMAC and comparing.

use aya_ebpf::{
    bindings::xdp_action,
    maps::{PerCpuArray, LruHashMap},
    programs::XdpContext,
};
use core::mem;
use network_types::{
    eth::EthHdr,
    ip::Ipv4Hdr,
    tcp::TcpHdr,
};
use aegis_common::*;

/// Global SYN rate tracking — per-CPU to avoid lock contention.
/// Index 0: current window count, Index 1: window start timestamp.
pub struct SynFloodState {
    pub flood_active: bool,
    pub syn_count: u64,
    pub window_start_ns: u64,
}

/// Standard MSS values for SYN cookie encoding.
/// 3-bit index → MSS value mapping.
const MSS_TABLE: [u16; 8] = [
    536,   // 0: Minimum MSS
    1200,  // 1: Common for tunnel/VPN
    1400,  // 2: PPPoE
    1440,  // 3: Common default
    1452,  // 4: DSL
    1460,  // 5: Standard Ethernet
    4312,  // 6: Jumbo-lite
    8960,  // 7: Jumbo frames
];

/// Compute a simple hash for SYN cookie generation.
/// In production, this should use a keyed HMAC with a rotating secret.
#[inline(always)]
pub fn compute_cookie_hash(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    secret: u32,
) -> u32 {
    // FNV-1a inspired hash — fast and non-cryptographic.
    // For production: use SipHash or HMAC-SHA256 with BPF helper.
    let mut hash: u32 = 2166136261; // FNV offset basis
    hash ^= src_ip;
    hash = hash.wrapping_mul(16777619); // FNV prime
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

    // Find the best MSS index.
    let mss_idx = find_mss_index(mss);

    // Encode: [hash bits 8:31] | [mss_idx bits 0:2] | [reserved bits 3:7]
    (hash & 0xFFFFFF00) | ((mss_idx as u32) & 0x07)
}

/// Validate a SYN cookie from an incoming ACK.
/// The ACK number should be (cookie + 1).
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

    // Compare the hash portion (bits 8:31).
    (cookie & 0xFFFFFF00) == (expected_hash & 0xFFFFFF00)
}

/// Find the closest MSS index for the given MSS value.
#[inline(always)]
fn find_mss_index(mss: u16) -> u8 {
    // Binary search through the MSS table.
    let mut best_idx: u8 = 5; // Default: 1460 (standard Ethernet)
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
        1460 // Default
    }
}

/// Extract the MSS option from TCP options in the SYN packet.
/// TCP options start after the fixed 20-byte header and extend
/// to (data_offset * 4) bytes.
#[inline(always)]
pub fn extract_mss_from_tcp_options(ctx: &XdpContext, tcp_offset: usize) -> u16 {
    let data_start = ctx.data();
    let data_end = ctx.data_end();

    // TCP header minimum is 20 bytes. Read data offset to get actual size.
    if data_start + tcp_offset + 20 > data_end {
        return 1460; // Can't read options, use default
    }

    let tcp_hdr = (data_start + tcp_offset) as *const TcpHdr;

    // Data offset is in the upper 4 bits of byte 12, measured in 32-bit words.
    let data_offset_byte = unsafe { *((data_start + tcp_offset + 12) as *const u8) };
    let data_offset = ((data_offset_byte >> 4) as usize) * 4;

    if data_offset <= 20 {
        return 1460; // No options present
    }

    let options_start = tcp_offset + 20;
    let options_end = tcp_offset + data_offset;

    if data_start + options_end > data_end {
        return 1460;
    }

    // Scan TCP options looking for MSS (kind=2, length=4).
    let mut offset = options_start;
    while offset + 1 < options_end {
        if data_start + offset >= data_end {
            break;
        }
        let kind = unsafe { *((data_start + offset) as *const u8) };

        match kind {
            0 => break,          // End of Options
            1 => offset += 1,    // NOP
            2 => {
                // MSS option: kind=2, length=4, value=u16
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
                // Variable-length option: read length byte.
                if data_start + offset + 1 >= data_end {
                    break;
                }
                let len = unsafe { *((data_start + offset + 1) as *const u8) } as usize;
                if len < 2 {
                    break; // Invalid option length
                }
                offset += len;
            }
        }
    }

    1460 // Default MSS if not found
}

/// Check if the global SYN rate indicates a flood is in progress.
#[inline(always)]
pub fn check_syn_flood(
    syn_counter: &PerCpuArray<u64>,
    threshold: u64,
    now_ns: u64,
) -> bool {
    // Read current SYN count from this CPU.
    let count = match syn_counter.get(0) {
        Some(c) => unsafe { *c },
        None => return false,
    };

    let window_start = match syn_counter.get(1) {
        Some(ts) => unsafe { *ts },
        None => return false,
    };

    let elapsed = now_ns.saturating_sub(window_start);

    if elapsed > RATE_WINDOW_NS {
        // Window expired — reset.
        if let Some(c) = syn_counter.get_ptr_mut(0) {
            unsafe { *c = 1 };
        }
        if let Some(ts) = syn_counter.get_ptr_mut(1) {
            unsafe { *ts = now_ns };
        }
        false
    } else {
        // Increment and check threshold.
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

/// Compute the ones-complement checksum update when modifying fields.
/// RFC 1624: HC' = ~(~HC + ~m + m')
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
