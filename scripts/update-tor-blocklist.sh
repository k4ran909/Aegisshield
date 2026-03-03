#!/bin/bash
# AegisShield Tor Exit Node Blocker
# Downloads the latest Tor exit node list and blocks them via iptables.
# Run via cron: 0 */6 * * * /root/Aegisshield/scripts/update-tor-blocklist.sh
#
# This blocks the TOR attack method from MHDDoS.

set -euo pipefail

BLOCKLIST_URL="https://check.torproject.org/torbulkexitlist"
IPSET_NAME="tor_exit_nodes"
LOG_FILE="/var/log/aegis-tor-blocklist.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"
}

# ── Install ipset if not present ──────────────────────
if ! command -v ipset &>/dev/null; then
    apt-get install -y -qq ipset
fi

# ── Create/flush ipset ───────────────────────────────
if ! ipset list "$IPSET_NAME" &>/dev/null; then
    ipset create "$IPSET_NAME" hash:ip maxelem 65536 timeout 86400
    log "Created ipset $IPSET_NAME"
fi
ipset flush "$IPSET_NAME"

# ── Download Tor exit node list ───────────────────────
TMP_FILE=$(mktemp)
if curl -sf --max-time 30 "$BLOCKLIST_URL" -o "$TMP_FILE"; then
    COUNT=0
    while IFS= read -r ip; do
        # Skip empty lines and comments
        [[ -z "$ip" || "$ip" =~ ^# ]] && continue
        # Validate IP format
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            ipset add "$IPSET_NAME" "$ip" timeout 86400 2>/dev/null || true
            ((COUNT++))
        fi
    done < "$TMP_FILE"

    log "Loaded $COUNT Tor exit nodes into $IPSET_NAME"
else
    log "ERROR: Failed to download Tor exit node list"
    rm -f "$TMP_FILE"
    exit 1
fi
rm -f "$TMP_FILE"

# ── Add iptables rule if not present ──────────────────
if ! iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
    iptables -I INPUT -m set --match-set "$IPSET_NAME" src -j DROP
    log "Added iptables DROP rule for $IPSET_NAME"
fi

log "Tor exit node blocklist updated successfully"
