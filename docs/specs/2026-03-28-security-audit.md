# ShadowLink Security Audit — 2026-03-28

## Summary

| Severity | Count | Key Issues |
|---|---|---|
| CRITICAL | 3 | TLS fingerprint не работает (Go игнорирует CipherSuites для TLS 1.3), fingerprint pool не подключён к transport, SSRF в CONNECT handler |
| HIGH | 6 | seq_num overflow, O(N) session lookup DoS, нет rate-limit handshake, нет проверки client_id, ключи не зануляются, SessionID в cleartext |
| MEDIUM | 8 | Spec/code расхождение nonce, error leak в CONNECT, data loss при полном channel, race condition в tunnel, key zeroing grace period, bitmap fragility, server key storage, empty client_id |
| LOW | 7 | Слабый default decoy, X-Request-ID leak, User-Agent inconsistency, entropy stability, double-close channel, heartbeat PRNG, probe InsecureSkipVerify |
| INFO | 4 | Forward secrecy OK, ClientHello replay = DoS not hijack, no UDP ASSOCIATE, polling model not true bidirectional |

## Priority Fix Order

### Before any deployment:
1. **C3: SSRF protection** — block private IPs in CONNECT handler
2. **H4: Client authentication** — whitelist client_ids or add PSK
3. **H3: Rate-limit handshakes** — per-IP limit

### Before DPI testing:
4. **C1+C2: Switch to uTLS** — Go crypto/tls fingerprint = instant detection
5. **L3: Fix User-Agent consistency** — one UA per session, match fingerprint

### Before production:
6. **H5: Zero key material** — call ZeroBytes() on all key lifecycle events
7. **H6: Encrypt SessionID in ServerHello** — remove plaintext sid from JSON
8. **H2: O(1) session lookup** — add session_id hint to token
9. **M3+M4: Fix race conditions and data loss** — mutex on tunnel, blocking channel send
10. **M1: Update spec** — reflect actual nonce/AAD implementation

## Full Details

See the security audit agent output for complete descriptions, file:line references, impact analysis and recommendations for all 28 findings.
