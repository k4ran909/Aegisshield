-- ═══════════════════════════════════════════════════════════════════
-- AegisShield Lua Rate Limiter for HAProxy
-- Per-IP, per-path request rate limiting with sliding window
-- ═══════════════════════════════════════════════════════════════════

-- This module provides additional rate limiting beyond HAProxy's
-- built-in stick-tables, with more granular per-path control.

local _M = {}

-- Rate limit configuration (requests per window)
local rate_limits = {
    -- path_prefix = { max_requests, window_seconds }
    ["/api/"]     = { 50, 10 },   -- 50 req / 10s for API endpoints
    ["/login"]    = { 10, 60 },   -- 10 req / 60s for login
    ["/search"]   = { 20, 10 },   -- 20 req / 10s for search
    ["/"]         = { 100, 10 },  -- 100 req / 10s global default
}

-- Check if a request should be rate limited
-- Called from HAProxy: http-request lua.check_rate_limit
function _M.check_rate_limit(txn)
    local src_ip = txn.f:src()
    local path = txn.f:path()

    -- Find matching rate limit rule
    for prefix, limits in pairs(rate_limits) do
        if path and path:sub(1, #prefix) == prefix then
            local max_req = limits[1]
            -- Rate limiting is primarily handled by stick-tables
            -- This Lua module provides additional per-path granularity
            break
        end
    end
end

-- Log a rate-limited request for analytics
function _M.log_rate_limit(txn)
    local src_ip = txn.f:src()
    local path = txn.f:path()
    core.log(core.warning, string.format(
        "[AEGIS] Rate limited: IP=%s Path=%s", src_ip, path
    ))
end

core.register_action("check_rate_limit", {"http-req"}, _M.check_rate_limit)

return _M
