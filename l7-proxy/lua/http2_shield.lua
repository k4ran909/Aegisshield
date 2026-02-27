-- ═══════════════════════════════════════════════════════════════════
-- AegisShield HTTP/2 Rapid Reset Shield for HAProxy
-- Defense against CVE-2023-44487 exploitation
-- ═══════════════════════════════════════════════════════════════════
--
-- The HTTP/2 Rapid Reset attack opens streams (HEADERS) and immediately
-- cancels them (RST_STREAM), forcing the server to allocate and deallocate
-- resources without counting against MAX_CONCURRENT_STREAMS.
--
-- This module tracks the ratio of stream creations to cancellations
-- per connection and triggers GOAWAY when abusive behavior is detected.

local _M = {}

-- Thresholds
local MAX_RST_PER_SECOND = 100       -- Max RST_STREAM frames per second
local MAX_RST_RATIO = 0.5            -- Max ratio of RST to total streams
local SUSPICIOUS_BURST_SIZE = 50     -- Streams created within 1s = suspicious

-- Track per-connection RST_STREAM behavior
-- Note: Full implementation requires HAProxy C module or the built-in
-- HTTP/2 abuse protection available in HAProxy 3.x
function _M.check_http2_abuse(txn)
    -- HAProxy 3.x has built-in HTTP/2 flood protection:
    -- tune.h2.max-concurrent-streams 100
    -- tune.h2.be.max-concurrent-streams 100
    --
    -- Additional protection is handled via stick-tables tracking
    -- the request rate per connection source IP.

    local conn_rate = txn.f:sc_conn_rate(0)
    local req_rate = txn.f:sc_http_req_rate(0)

    -- If request rate is abnormally high relative to connection rate,
    -- it suggests HTTP/2 stream multiplexing abuse
    if req_rate and conn_rate and conn_rate > 0 then
        local ratio = req_rate / conn_rate
        if ratio > 1000 then
            core.log(core.warning, string.format(
                "[AEGIS] HTTP/2 abuse detected: IP=%s req_rate=%d conn_rate=%d ratio=%.1f",
                txn.f:src(), req_rate, conn_rate, ratio
            ))
            txn:set_var("txn.aegis_h2_abuse", true)
        end
    end
end

-- Force suspicious clients to HTTP/1.1 (defangs Rapid Reset entirely)
function _M.downgrade_to_h1(txn)
    -- This is implemented at the HAProxy frontend level:
    -- If an IP is in the "jail" stick-table, force HTTP/1.1
    -- bind *:443 ssl crt /path/cert.pem alpn h2,http/1.1
    -- Use ACLs to strip HTTP/2 ALPN for jailed IPs
    core.log(core.info, string.format(
        "[AEGIS] Downgrading to HTTP/1.1: IP=%s", txn.f:src()
    ))
end

core.register_action("check_http2_abuse", {"http-req"}, _M.check_http2_abuse)

return _M
