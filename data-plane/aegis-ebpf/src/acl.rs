//! Edge Network Firewall — ACL Engine (inspired by OVH ENF)
//!
//! Evaluates packets against a priority-ordered rule table.
//! Rules are stored in a BPF Array map (indexed by priority).
//! The engine scans rules 0..MAX_ACL_RULES and returns the action
//! of the first matching rule.
//!
//! Supported match criteria:
//! - IP protocol (TCP=6, UDP=17, ICMP=1, any=0)
//! - Destination port
//! - Source port
//!
//! Actions: PASS (1) or DROP (0)

use aya_ebpf::maps::Array;
use aegis_common::{AclRule, MAX_ACL_RULES};

/// Evaluate the ACL rules for a given packet.
///
/// Returns:
/// - `Some(true)` → Rule matched, action = PASS
/// - `Some(false)` → Rule matched, action = DROP
/// - `None` → No rule matched (default: PASS)
#[inline(always)]
pub fn evaluate_acl(
    acl_rules: &Array<AclRule>,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
) -> Option<bool> {
    // Scan rules in priority order (0 = highest priority).
    // We unroll the first N iterations for performance.
    let mut i: u32 = 0;
    while i < MAX_ACL_RULES {
        if let Some(rule) = acl_rules.get(i) {
            // Skip disabled rules.
            if rule.enabled == 0 {
                i += 1;
                continue;
            }

            // Match protocol (0 = wildcard / any).
            if rule.protocol != 0 && rule.protocol != protocol {
                i += 1;
                continue;
            }

            // Match destination port (0 = wildcard).
            if rule.dst_port != 0 && rule.dst_port != dst_port {
                i += 1;
                continue;
            }

            // Match source port (0 = wildcard).
            if rule.src_port != 0 && rule.src_port != src_port {
                i += 1;
                continue;
            }

            // Rule matched — return action.
            // action: 0 = DROP, 1 = PASS
            return Some(rule.action == 1);
        }

        i += 1;
    }

    // No rule matched — default policy is PASS.
    None
}
