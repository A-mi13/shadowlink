# ShadowLink Security Audit v2 — Final Pre-Deploy Review

## Summary: 1 CRITICAL, 5 HIGH, 8 MEDIUM, 5 LOW, 6 INFO

## Honest Assessment (from auditor)

**Cryptография — solid.** X25519, HKDF, AES-GCM, NaCl Box — всё правильно. Forward secrecy работает.

**Главная слабость — архитектурная, не криптографическая:**
HTTP/1.1 с Connection: close = сотни коротких TLS-соединений к одному хосту.
Ни один реальный браузер так не делает. Это ГЛАВНАЯ поверхность детекции для ТСПУ.
Переход на HTTP/2 с мультиплексированием (Phase 1b) критически важен.

## Must Fix Before Deploy

| # | Issue | Fix |
|---|---|---|
| C1 | SessionID в cleartext в ServerHello JSON | Убрать поле sid, использовать только encrypted token |
| H3 | Keys не зануляются при удалении сессии | Добавить Session.Destroy() с ZeroBytes |
| H4 | CONNECT error leak | Отправлять "CONNECT_FAIL" без деталей |
| H5 | seq_num overflow без принудительного rekey | Принудительный rekey при seq > 2^31 |

## Must Fix Before DPI Testing

| # | Issue | Fix |
|---|---|---|
| M1 | TLS fingerprint/User-Agent mismatch | Один профиль на сессию, UA = fingerprint |
| M5 | Cover traffic отличается от data traffic | Одинаковая JSON структура для обоих |
| M8 | TLS 1.2 разрешён (downgrade attack) | MinVersion = TLS 1.3 на сервере |
| M6 | Rate limiter бесконечно растёт | Cleanup + лимит записей + не доверять XFF |

## Architectural (Phase 1b)

**L1 + I6: HTTP/1.1 Connection: close — главная проблема.**
Сотни коротких TCP-соединений != реальный браузер.
ML-классификатор определит ShadowLink за 30 секунд с >95% точностью.
**Решение: HTTP/2 multiplexing или QUIC** (уже в плане Phase 1b).

## What's Actually Good

- Forward secrecy ✅
- SSRF protection ✅
- uTLS browser fingerprinting ✅
- Decoy site for active probing ✅
- Rate limiting + client auth ✅
- 16KB threshold defense ✅
- Key rotation framework ✅
