# ShadowLink Server — Installation Guide

Audience: whoever provisions a VPS. You do not need to read Go source.

Source of truth for this document: `install-server.sh`,
`cmd/shadowlink-server/main.go`, `server/fileconfig.go`, `server/config.go`,
`server/decoy_snapshots.go`, `.github/workflows/release.yml` (repo
`A-mi13/shadowlink`). Every flag and YAML key below was read from that source,
not from prose.

**Verification legend used throughout**

| Mark | Meaning |
|---|---|
| VERIFIED | Read in the shipped source, or exercised against the real server binary |
| UNVERIFIED | Not run on a real VPS — stated as unknown, not as fact |

The installer as a whole is **UNVERIFIED**: it has never been executed on a
clean VPS. What was checked, and how, is listed in §11.

---

## 1. What you get

One command on a clean Debian/Ubuntu box produces:

| Component | Location |
|---|---|
| Server binary | `/opt/shadowlink/shadowlink-server` |
| Config | `/etc/shadowlink/config.yaml` |
| Static key (X25519) | `/etc/shadowlink/server.key` |
| Decoy site | `/var/www/decoy/index.html` |
| nginx site | `/etc/nginx/sites-available/shadowlink-443` |
| systemd unit | `/etc/systemd/system/shadowlink.service` |

and it prints the `sl://` link your client needs.

The resulting topology — this is fixed, not a preference:

```
client → uTLS (Chrome) → :443 direct to the bare origin IP
       → nginx (TLS termination) → 127.0.0.1:10443 → shadowlink-server
```

**nginx is mandatory.** Go's `net/http` emits non-browser HTTP/2 SETTINGS,
which is a JA3-level tell. The Go process therefore never faces the internet
directly; it binds loopback only. Do not "simplify" this by pointing the server
at `:443`.

**No CDN, ever.** Not Cloudflare, not domain fronting, not a proxy in front.
Traffic goes direct to the origin IP. The censor's decision is made inline at
the subscriber's first hop, so putting a CDN in front changes nothing about
detection while adding a party that can see or break the connection.

---

## 2. Requirements

| Requirement | Why |
|---|---|
| Debian or Ubuntu, x86_64 | The installer uses `apt` and writes a systemd unit. The release asset is built for `linux/amd64` only. |
| root | Needs systemd, nginx, and port 443. |
| A domain with an **A record already pointing at this VPS** | Let's Encrypt validates over HTTP; DNS must resolve *before* you run the installer. |
| Ports 80 and 443 reachable | 80 for ACME, 443 for traffic. |
| `curl`, `systemctl` | Checked up front; the installer aborts if missing. |
| A GitHub token, **or** a binary you upload yourself | See §3. |

A 1 vCPU / 1 GB VPS is enough to start. Defaults are sized for 2 vCPU / 2 GB
(`MaxClients: 500`).

---

## 3. Why a token is required

`install-server.sh` cannot be run the way Reality, Xray, or sing-box are
installed:

```bash
# This DOES NOT WORK for ShadowLink.
bash <(curl -sSL https://raw.githubusercontent.com/A-mi13/shadowlink/main/install-server.sh)
```

The repository is **private**, and that is a deliberate decision: the source of
a steganographic protocol should not be handed to the adversary it is designed
to evade. GitHub does not serve private content anonymously, and — this is the
part that bites — it answers with **HTTP 404**, not 403. Measured on this
repository:

| Anonymous request | Result |
|---|---|
| `raw.githubusercontent.com/.../install-server.sh` | 404 |
| release asset `v0.2.0/shadowlink-server-linux` | 404 |

So "no access" is indistinguishable from "no such file". The installer
therefore refuses to guess: with no token and no local binary it stops
immediately and says which of the two you need, instead of downloading a 404
error page and failing later with something confusing.

### Issuing a token

Use a **fine-grained personal access token**:

1. GitHub → Settings → Developer settings → Personal access tokens →
   Fine-grained tokens → Generate new token.
2. Repository access: **Only select repositories** → `A-mi13/shadowlink`.
3. Permissions: **Contents: Read-only**. Nothing else.
   `read:org` is *not* needed.
4. Set the shortest expiry you can live with.

A classic token with the `repo` scope also works, but it grants far more than
this installer needs.

The token is read **only from the environment** (`GITHUB_TOKEN`, or `GH_TOKEN`
as a synonym). It is never written to a file, never passed as a command-line
argument (arguments are visible in `ps` to every user on the box), and never
printed — including in error messages, which show the URL but never the
`Authorization` header.

### If the repository ever becomes public

Partial publication after beta is possible. If that happens, the download path
collapses to a plain `curl`, and the command in §4 loses its
`Authorization` header. Nothing else in this document changes. The
upload-your-own-binary path (§4, option B) keeps working either way.

---

## 4. Install

### Option A — token (recommended)

```bash
export GITHUB_TOKEN=github_pat_xxxxxxxx

bash <(curl -H "Authorization: Bearer $GITHUB_TOKEN" -sSL \
  https://raw.githubusercontent.com/A-mi13/shadowlink/main/install-server.sh) \
  --domain vpn.example.com \
  --email admin@example.com
```

The installer pulls the `shadowlink-server-linux` asset from the latest release
through the GitHub API. For private repositories this **must** go through
`api.github.com/repos/.../releases/assets/<id>` with
`Accept: application/octet-stream` — the familiar
`/releases/download/<tag>/<file>` URL redirects to a CDN that drops the
`Authorization` header and answers 404.

### Option B — upload the binary yourself

Useful when the VPS has no token, or when you want to install the exact binary
you just built.

```bash
# On your machine:
bash build-server.sh
scp bin/shadowlink-server-linux root@vps:/tmp/
scp install-server.sh root@vps:/tmp/

# On the VPS:
SL_BINARY=/tmp/shadowlink-server-linux \
  bash /tmp/install-server.sh --domain vpn.example.com --email admin@example.com
```

### Options

| Flag / env | Meaning |
|---|---|
| `--domain <fqdn>` | Required. Goes into nginx `server_name`, the certificate, and the `sl://` link. |
| `--email <addr>` | Required for Let's Encrypt. Omit only with `--cert/--key` or `--skip-cert`. |
| `--binary <path>` / `SL_BINARY` | Install this file instead of downloading. |
| `--cert <path> --key <path>` | Use an existing certificate instead of certbot. Both or neither. |
| `--skip-cert` | Do not touch certificates (you manage them). |
| `--skip-nginx` | Do not write the nginx config. **You must then configure it yourself** — see §6. |
| `--yes` | No prompts. Required for non-interactive runs. |
| `GITHUB_TOKEN` / `GH_TOKEN` | Token for the private release. |
| `SL_REPO` | `owner/repo`, default `A-mi13/shadowlink`. |
| `SL_RELEASE_TAG` | Release tag, default `latest`. |

---

## 5. What the installer does, step by step

Everything that can fail is checked **before** anything is written. A
half-installation is worse than a refusal: afterwards it is unclear what
already happened, and systemd reports `failed` with no useful cause.

1. **Environment.** root; Debian/Ubuntu; x86_64; `curl` and `systemctl`
   present; port 443 free (or held by nginx, which is expected on reinstall);
   port 10443 free (or held by our own service). Domain is syntax-checked —
   it is interpolated into nginx config and shell heredocs, so a domain
   containing shell metacharacters is rejected outright.
2. **Packages.** `nginx`, and `certbot`/`python3-certbot-nginx` when a
   certificate is needed. Already-present packages are skipped.
3. **Binary.** Downloaded via API or copied from `SL_BINARY`. Then verified:
   the ELF magic is checked (a 404 page saved to disk is not an ELF file), and
   `-gen-key` is executed as a liveness probe — it touches no disk state and
   catches a wrong-architecture or corrupt binary before it reaches production.
   An existing binary is backed up with a timestamp first.
4. **User and directories.** System user `shadowlink`, no shell, no home.
   `/etc/shadowlink` is `0750 root:shadowlink`.
5. **Key.** `-gen-key` produces the X25519 pair; the private half (64 hex
   chars) is written to `/etc/shadowlink/server.key`, mode `0640`.
   **An existing key is never overwritten** — see §8.
6. **Decoy site.** Generated, because the repository ships none — see §7.
7. **Config.** `/etc/shadowlink/config.yaml`, then validated with the server's
   own `-validate-config`. An existing config is left alone.
8. **Certificate.** certbot issues one against a temporary HTTP vhost, unless
   you supplied `--cert/--key` or a certificate already exists.
9. **nginx.** Site config plus a `map $connection_upgrade` block, then
   `nginx -t`. A failing `nginx -t` aborts the install.
10. **systemd.** Unit written, enabled, started.
11. **Verification.** `systemctl is-active`, then an actual HTTPS request
    through nginx over loopback with the right `Host` header — "active" only
    means the process is alive, not that it answers. The response is also
    checked for the JSON-LD baseline.
12. **Client link.** `export-client-config` prints the `sl://` URL, with port
    443 forced (the config's `listen` is the internal 10443, which would
    otherwise end up in the link).

---

## 6. The nginx config, and why it looks like that

```nginx
location / {
    proxy_pass http://127.0.0.1:10443;
    proxy_http_version 1.1;
    proxy_set_header Upgrade    $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_read_timeout 86400;
    proxy_send_timeout 86400;
    proxy_buffering off;
    proxy_request_buffering off;
}
```

Four decisions that are not cosmetic:

- **One `location` for everything.** The server itself routes by method,
  `Content-Type`, and the `Upgrade` header: `POST` + `application/json` → VPN
  session, `Upgrade: websocket` → WS transport, everything else → decoy site.
  Splitting this across nginx `location` blocks would move that decision into
  nginx and break the decoy branch, which is what an active prober sees.
- **No `http2`.** WebSocket upgrade requires HTTP/1.1. Enabling `http2` on the
  443 listener makes nginx negotiate h2 with the client, and the upgrade path
  disappears.
- **`proxy_read_timeout`/`proxy_send_timeout` at 86400.** nginx defaults to 60
  seconds, which falls *inside* the server's WebSocket ping interval
  (22.5–90 s). Left at the default, nginx tears down long-lived WS connections
  itself — and on the client that is indistinguishable from a middlebox cutting
  the connection, i.e. you would be debugging a censor that is not there.
- **`$connection_upgrade` via `map`, not a literal.** On ordinary (non-WS)
  requests `Upgrade` is empty; a hardcoded `Connection: upgrade` would break
  keep-alive for decoy traffic. The map lives in
  `/etc/nginx/conf.d/shadowlink-upgrade-map.conf` because `map` is only valid
  at `http{}` level.

The management API is proxied at `/_mgmt/` and restricted to `127.0.0.1` with
`deny all`. Its key sits in the config file in clear text; it must not be
reachable from outside.

---

## 7. The decoy site — read this

**The repository contains no decoy site.** No directory, no template. The
installer generates a minimal one, and you should treat that as a starting
point, not a finished product.

Why it cannot simply be skipped: with no decoy directory the server falls back
to a built-in "under construction" placeholder that carries **no Schema.org
block**. That block is the body-carrier for the rate-limit signal. Without it
the only remaining carrier is the `X-SL-RL` header — a header no real website
emits, i.e. a direct ShadowLink signature for an active prober.

The generated template satisfies the loader's invariants
(`server/decoy_snapshots.go`), all of which are enforced fail-fast at startup:

- a `<script type="application/ld+json">` block,
- `identifier.@type == "PropertyValue"`,
- a non-empty `identifier.propertyID`,
- `identifier.value` **exactly 80 bytes** (padded with trailing semicolons),
- file under 256 KB.

The JSON-LD is emitted as a **single line, flat object**, deliberately. The
client detector matches it with the regex `>(\{[^<]+\})</script>`, which
survives neither line breaks with nesting nor a `<` inside. Pretty-printing that
block would silently kill the body-carrier.

### Known limitation: `propertyID` is the legacy literal

The generated template uses `propertyID: "rl-state"`. The correct value is
derived per host by HMAC (`core.DeriveRLPropertyID`), which bash cannot compute
— and **no template generator exists in the repository**; `core/rlpropertyid.go`
says so in as many words ("receiving side only", status 2026-08-08).

Consequences, stated plainly:

- It works. The client still accepts the legacy literal
  (`client/ratelimit_carriers.go`), so the rate-limit channel is live.
- The literal is identical on every server, so one internet-wide scan for that
  substring enumerates every host that uses it. With a single server this costs
  nothing — enumerating a fleet of one from itself yields what the scanner
  already had. **Before you deploy a second host, regenerate the template with
  a per-host ID.**

### Replacing it

Put your own site in `/var/www/decoy/`. Keep a valid JSON-LD baseline in
`index.html`, or the server will refuse to start (that fail-fast is
intentional; the alternative was silent degradation to header-only). To deploy
without a baseline, add `-decoy-snapshot-strict=false` to `ExecStart` and
accept the header-only risk.

The installer does not overwrite an existing `index.html` that already contains
a JSON-LD block.

---

## 8. Idempotency

Re-running the installer on a working box is safe. Specifically:

| Item | On re-run |
|---|---|
| **Server key** | **Never regenerated.** |
| Config | Left as-is if present. |
| Decoy `index.html` | Left as-is if it has a JSON-LD block; otherwise you are asked. |
| Binary | Replaced; the old one is backed up as `.bak-<timestamp>`. |
| nginx config | Overwritten. Local edits are lost. |
| systemd unit | Overwritten. |
| Certificate | Reused if already issued. |

The key rule matters most: the public half of that key is embedded in every
`sl://` link you have handed out. Regenerating it breaks the handshake for
every existing client at once, with no error message that points at the cause.
The installer will not do it even with `--yes`.

To deliberately rotate: stop the service, delete
`/etc/shadowlink/server.key`, re-run, and reissue every client link.

---

## 9. After installation — what you must do by hand

The installer deliberately does not touch these.

**DNS.** The A record for your domain must point at this VPS *before* you run
the installer, because Let's Encrypt validates over HTTP. The installer cannot
create it — the domain lives at your registrar, and a wrong guess here produces
a certificate for a name you do not control. If certbot fails, this is the
first thing to check.

**Firewall.** Open `80/tcp` and `443/tcp`, both in your provider's panel
(security groups are outside the VPS) and in the host firewall if one is
active:

```bash
ufw allow 80/tcp && ufw allow 443/tcp
```

The installer does not manage firewall rules: opening ports on someone's
machine without asking is a change with security consequences, and provider
firewalls are unreachable from inside the box anyway. Do **not** expose 10443
or 9443 — they are loopback-only by design.

**Client link distribution.** The printed `sl://` URL is credential material.
Send it over a channel you trust and keep it out of version control.

---

## 10. Operations

```bash
systemctl status shadowlink
journalctl -u shadowlink -f
systemctl restart shadowlink
```

### Update the server

The installer replaces the binary and keeps the key and config:

```bash
export GITHUB_TOKEN=...
bash install-server.sh --domain vpn.example.com --skip-cert --yes
```

Note it rewrites the nginx config. For an established production box,
`deploy-round18.sh` is the better tool: it uploads from your machine over ssh,
verifies the hash before and after the switch, and touches nothing else.

Roll back to the previous binary:

```bash
systemctl stop shadowlink
cp /opt/shadowlink/shadowlink-server.bak-<timestamp> /opt/shadowlink/shadowlink-server
systemctl start shadowlink
```

### Uninstall

```bash
systemctl disable --now shadowlink
rm -f /etc/systemd/system/shadowlink.service
systemctl daemon-reload

rm -rf /opt/shadowlink /var/www/decoy
rm -f /etc/nginx/sites-enabled/shadowlink-443 \
      /etc/nginx/sites-available/shadowlink-443 \
      /etc/nginx/conf.d/shadowlink-upgrade-map.conf
nginx -t && systemctl reload nginx

userdel shadowlink

# Last — this destroys the identity. Every sl:// link you issued dies with it.
rm -rf /etc/shadowlink
```

Certificates are left in `/etc/letsencrypt/`; remove them with
`certbot delete --cert-name <domain>` if you are done with the domain.

---

## 11. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `нужен GITHUB_TOKEN … либо SL_BINARY` | No binary source. See §3–4. |
| API returns 404 | For a private repo this is almost always *no access*, not a missing release. Check the token has Contents: Read on this repository. |
| API returns 401 | Token expired or mistyped. |
| `в релизе … нет ассета shadowlink-server-linux` | Release exists but has no server asset — check the release page, or use `SL_BINARY`. |
| `это не ELF-бинарь` | The download produced an error page, or the wrong file was passed. |
| `бинарь не запускается на этой машине` | Wrong architecture (the release is amd64-only) or a corrupt file. |
| certbot fails | A record does not point here, or 80/tcp is blocked. Check with `dig +short <domain>`. |
| Service dead, log mentions `decoy snapshot` | The decoy has no valid Schema.org baseline. See §7. |
| Service dead, `management key too short` | The mgmt key must be ≥32 chars when bind is not loopback. |
| Client connects, then drops after ~60 s | nginx `proxy_read_timeout` left at its default. See §6. |
| WebSocket never upgrades | `http2` enabled on the 443 listener. See §6. |
| Decoy answers, VPN does not | Verify `behind_proxy: true`; without it every client IP reads as 127.0.0.1 and rate limiting misfires. |

---

## 12. What was verified, and what was not

Honest status, because "the script exists" is not "the script works".

**Exercised against the real server binary (VERIFIED):**

- `-gen-key` output parsing — the `awk` expression extracts a 64-char hex key;
  two runs produce different keys, which is what makes protecting the existing
  key file meaningful.
- The generated YAML passes the server's own `-validate-config` (exit 0).
- `export-client-config` produces an `sl://` link that carries the **public**
  key derived from that private key, on port **443** — not the internal 10443,
  and with no private key material in it.
- The generated decoy template passes the real `LoadDecoySnapshots`, and its
  80-byte value slot matches `MakeBaselineValue()` byte for byte.
- The same template is matched by the client's `jsonLDRe` regex, and the
  client accepts the `rl-state` propertyID — i.e. the body-carrier works on
  both sides.
- Every flag the installer calls (`-gen-key`, `-validate-config`,
  `-config`, `export-client-config -config/-domain/-port/-format`) exists in
  `main.go` / `export.go`.

**Checked statically (VERIFIED):**

- `bash -n` — the script parses.
- Exit codes for `--help` (0), unknown argument (1), missing `--domain` (1),
  non-root (1).
- Domain validation rejects `localhost`, spaces, leading dot or dash, trailing
  dot, and command injection (`$(...)`, backticks, `;`) — this matters because
  the domain is interpolated into nginx config and shell heredocs.
- The generated nginx config: balanced braces, every directive terminated,
  all WS-critical directives present, `http2` absent, exactly two `location`
  blocks in the 443 server, `/_mgmt/` behind `deny all`, no CDN references,
  and all nginx `$variables` surviving shell interpolation intact.
- The GitHub asset-id parser, against both minified and pretty-printed API
  JSON, including the trap that the release object has its own `id` field.
  (The first version of the parser only worked on minified JSON; the test
  caught it.)

**NOT verified — requires a real VPS (UNVERIFIED):**

- The installer has **never been run end to end**. Nothing below was executed.
- `nginx -t` on the generated config. Only structure was checked; nginx itself
  never parsed it.
- Package installation, certbot issuance, the ACME flow.
- systemd: whether the unit starts, and in particular whether the hardening
  directives (`ProtectSystem=strict`, `SystemCallFilter=@system-service`,
  `RestrictAddressFamilies`) are compatible with what the server actually does
  at runtime. **This is the most likely thing to fail on first run** — if the
  service dies immediately with no useful log, comment out the hardening block
  and retry to confirm.
- The GitHub download path against a real private release (no token was used).
- Port-conflict detection, and the behaviour of the OS/architecture checks on
  an actual Debian box.
- Whether a real client completes a handshake against a box installed this way.
