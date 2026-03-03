#!/bin/bash
# AegisShield L7 Proxy Setup — Nginx DDoS Protection Layer
# Run on VPS as root: bash deploy/setup-l7-proxy.sh

set -euo pipefail

GREEN='\033[1;32m'
CYAN='\033[1;36m'
RESET='\033[0m'

echo -e "${CYAN}Setting up AegisShield L7 Proxy Protection...${RESET}"

# ── Install Nginx ──────────────────────────────────────
echo -e "${GREEN}[1/4] Installing Nginx...${RESET}"
apt-get update -qq
apt-get install -y -qq nginx

# ── Install DDoS config ───────────────────────────────
echo -e "${GREEN}[2/4] Installing DDoS protection config...${RESET}"

# Backup default config
cp /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/default.bak 2>/dev/null || true

# Remove default site
rm -f /etc/nginx/sites-enabled/default

# Copy our hardened config
cp "$(dirname "$0")/nginx-ddos.conf" /etc/nginx/conf.d/aegisshield-l7.conf

# ── Tune Nginx for DDoS ──────────────────────────────
echo -e "${GREEN}[3/4] Tuning Nginx worker settings...${RESET}"
cat > /etc/nginx/conf.d/aegis-tuning.conf << 'EOF'
# AegisShield Nginx Tuning
# Increase worker connections for DDoS resilience
# Add to nginx.conf events block if needed

# Limit request body (STRESS attack defense)
client_max_body_size 10M;

# Reset timed out connections (frees resources faster)
reset_timedout_connection on;

# Don't send nginx version (info leak)
server_tokens off;
EOF

# ── Test + Restart ────────────────────────────────────
echo -e "${GREEN}[4/4] Testing and restarting Nginx...${RESET}"
nginx -t
systemctl restart nginx
systemctl enable nginx

echo ""
echo -e "${CYAN}"
cat << 'DONE'
+====================================================+
|  ✓ L7 Proxy Protection Active!                      |
+====================================================+
|                                                     |
|  DEFENSES ENABLED:                                  |
|    ✓ Request rate limiting (10 req/s per IP)        |
|    ✓ POST rate limiting (5 req/s per IP)            |
|    ✓ Connection limiting (50 per IP)                |
|    ✓ Slowloris protection (10s timeouts)            |
|    ✓ Request body size limit (10MB)                 |
|    ✓ Bad User-Agent blocking                        |
|    ✓ WordPress XMLRPC exploit blocking              |
|    ✓ Apache Range header exploit blocking           |
|    ✓ Slow-read (DOWNLOADER) protection              |
|    ✓ Security headers                               |
|                                                     |
|  CONFIG: /etc/nginx/conf.d/aegisshield-l7.conf      |
|                                                     |
|  NOTE: Update proxy_pass in the config to point     |
|  to your actual application backend port.           |
|                                                     |
+====================================================+
DONE
echo -e "${RESET}"
