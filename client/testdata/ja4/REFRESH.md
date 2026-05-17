# JA4 Reference Fixture — Refresh Procedure

The fixture in this directory pins a deterministic JA4-shaped fingerprint for
the custom Chrome 133 + X25519MLKEM768 ClientHello produced by
`pqClientHelloSpec()`. Tests in `utls_pq_test.go` use it as a regression
canary: any change to the spec, to utls, or to bogdanfinn that shifts the
on-wire ClientHello bytes will fail the JA4 assertion.

The hash is **NOT** the official JA4 algorithm — it is a deterministic
SHA-256-prefix derived from a stable subset of `PubClientHelloMsg` fields.
That keeps the test self-contained (no external JA4 dependency) while still
serving as a wire-level diff alarm. The official JA4 SHOULD be computed
alongside via Wireshark / FoxIO `ja4` tooling whenever a deploy runs against
a real DPI lab — record both in the field-validation log.

## When to Refresh

You MUST regenerate the fixture if any of these change:

- `pqClientHelloSpec()` body in `utls_http.go`
- `utlsProfileForFingerprint(...).ProfileChrome` mapping
- `github.com/refraction-networking/utls` version bumped (any change in the
  Chrome 133 spec or in the way MLKEM key-share / supported-groups serialize)
- `X25519MLKEM768` CurveID renamed or its numeric value changes (currently
  `0x11ec` / 4588)

You SHOULD refresh after deliberate ALPN / GREASE behavior changes too;
those flow through the same hash even though they do not break the PQ
property the fixture exists to guard.

## Refresh Procedure

1. Replace the file contents with the placeholder marker:

   ```
   PLACEHOLDER_REPLACE_AFTER_FIRST_TEST_RUN
   ```

2. Run the JA4 test in verbose mode:

   ```bash
   cd shadowlink
   go test ./client/ -run TestClientHelloBytes_JA4MatchesChromeReference -v -count=1
   ```

   The test sees the placeholder, recomputes the deterministic hash, logs it
   via `t.Logf("computed JA4 = ...")`, and SKIPs (does not fail). Capture
   the printed hash from the log line.

3. Paste the hash (single line, no trailing whitespace beyond a final
   newline) into `chrome_133_pq.txt`.

4. Re-run the test:

   ```bash
   go test ./client/ -run TestClientHelloBytes_JA4MatchesChromeReference -count=1
   ```

   It should now PASS. If it does not, the fixture and computed hash are out
   of sync — re-do steps 1-3 cleanly.

5. Commit the new fixture in the same change that motivated the refresh, and
   record the refresh in the CHANGELOG below.

## CHANGELOG

| Date       | Old hash        | New hash                                                          | Reason                                            |
|------------|-----------------|-------------------------------------------------------------------|---------------------------------------------------|
| 2026-04-26 | (placeholder)   | ba63e11f4a1e87d665fa04710fa07f3ff060ddf3295c2fe55af4909afda469a8 | T1.1 fixture established alongside PQ ClientHello (GREASE-normalized) |
| 2026-04-26 | ba63e11f4a1e87d665fa04710fa07f3ff060ddf3295c2fe55af4909afda469a8 | 1b3a4dd8a6b43fa43bd8a2ab6619a17da08f733d67d56db98a181ba217714fb3 | Refreshed after C1 fix (removed duplicate MLKEM keyshare from pqClientHelloSpec). |
