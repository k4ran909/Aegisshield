-- ═══════════════════════════════════════════════════════════════════
-- AegisShield JA4+ TLS Fingerprinting for HAProxy
-- Passive TLS Client Hello analysis for botnet detection
-- ═══════════════════════════════════════════════════════════════════
--
-- JA4+ fingerprints the unencrypted Client Hello during TLS handshake.
-- The fingerprint is derived from: TLS version, cipher suites, extensions,
-- elliptic curves, and their ordering.
--
-- Because the TLS stack is deeply integrated into the client software,
-- this fingerprint cannot be easily spoofed by changing HTTP headers.
-- A Python bot has a vastly different fingerprint than Chrome or Firefox.

local _M = {}

-- Known botnet / scanner JA4+ fingerprint hashes
-- These are updated from threat intelligence feeds
local known_bad_fingerprints = {
    -- Python requests library
    ["t13d1516h2_8daaf6152771_b0da82dd1658"] = "python-requests",
    -- curl/libcurl
    ["t13d1715h2_5b57614c22b0_3d5424432f57"] = "curl",
    -- Go net/http (often used in DDoS tools)
    ["t13d1516h2_8daaf6152771_02713d6af862"] = "go-http-client",
    -- Known DDoS botnet signatures (examples)
    ["t13d1110h2_deadbeef1234_cafebabe5678"] = "mirai-variant",
}

-- Allowlisted fingerprints (legitimate browsers)
local known_good_fingerprints = {
    -- Chrome 120+ on Windows
    ["t13d1516h2_8daaf6152771_e5627efa2ab1"] = "chrome",
    -- Firefox 120+ on Windows
    ["t13d1516h2_8daaf6152771_b1ff8ab2c16b"] = "firefox",
    -- Safari on macOS
    ["t13d1516h2_8daaf6152771_d8469cd2a9b6"] = "safari",
}

-- Check the JA4+ fingerprint of an incoming connection
-- Called from HAProxy: http-request lua.check_ja4_fingerprint
function _M.check_ja4_fingerprint(txn)
    -- HAProxy provides ssl_fc_ja4 as a fetch function
    -- This requires HAProxy 3.x with JA4 support compiled in
    local ja4 = txn.f:ssl_fc_ja4()

    if ja4 == nil or ja4 == "" then
        -- No TLS fingerprint available (plain HTTP or unsupported)
        return
    end

    -- Check against known-bad fingerprints
    local bad_match = known_bad_fingerprints[ja4]
    if bad_match then
        core.log(core.warning, string.format(
            "[AEGIS] Blocked bot by JA4+: IP=%s fingerprint=%s match=%s",
            txn.f:src(), ja4, bad_match
        ))
        -- Set a variable that HAProxy ACL can check
        txn:set_var("txn.aegis_ja4_blocked", true)
        txn:set_var("txn.aegis_ja4_match", bad_match)
        return
    end

    -- Check against known-good fingerprints
    local good_match = known_good_fingerprints[ja4]
    if good_match then
        txn:set_var("txn.aegis_ja4_browser", good_match)
        return
    end

    -- Unknown fingerprint — could be legitimate or a new bot
    -- Log for analysis, but don't block
    core.log(core.info, string.format(
        "[AEGIS] Unknown JA4+ fingerprint: IP=%s fingerprint=%s",
        txn.f:src(), ja4
    ))
end

core.register_action("check_ja4_fingerprint", {"http-req"}, _M.check_ja4_fingerprint)

return _M
