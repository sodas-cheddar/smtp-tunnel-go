# Quick Start — SMTP Tunnel Proxy (Go)

This ZIP contains everything you need to run the Go version of the
SMTP Tunnel Proxy. You do **not** need Go installed unless you want to
modify the source code — prebuilt binaries for every common platform
are in `release/`.

---

## What's in this ZIP

```
smtp-tunnel-go/
├── README.md                  ← Full documentation (read this first)
├── TECHNICAL.md               ← In-depth protocol & security analysis
├── LICENSE
├── QUICKSTART.md              ← This file
│
├── install.sh                 ← One-liner installer for the VPS
├── Makefile                   ← Build targets (only needed if you modify source)
├── Dockerfile                 ← Multi-stage distroless container build
├── go.mod, go.sum             ← Go module metadata (only needed for source builds)
│
├── config.yaml.example        ← Template config (install.sh generates the real one)
├── users.yaml.example         ← Template users file (adduser generates the real one)
│
├── bin/                       ← Prebuilt binaries for YOUR host (linux amd64)
│   ├── smtp-tunnel-go             ← All-in-one: server + adduser + deluser + ...
│   └── smtp-tunnel-client         ← Standalone client (shipped in user ZIPs)
│
├── release/                   ← Prebuilt binaries for all common platforms
│   ├── smtp-tunnel-go-linux-amd64
│   ├── smtp-tunnel-go-linux-arm64
│   ├── smtp-tunnel-go-darwin-amd64      (macOS Intel)
│   ├── smtp-tunnel-go-darwin-arm64      (macOS Apple Silicon)
│   ├── smtp-tunnel-go-windows-amd64.exe
│   ├── smtp-tunnel-client-linux-amd64
│   ├── smtp-tunnel-client-linux-arm64
│   ├── smtp-tunnel-client-darwin-amd64
│   ├── smtp-tunnel-client-darwin-arm64
│   └── smtp-tunnel-client-windows-amd64.exe
│
├── cmd/                       ← Source: binary entry points
│   ├── smtp-tunnel-go/main.go        ← All-in-one binary
│   └── smtp-tunnel-client/main.go    ← Standalone client binary
│
└── internal/                  ← Source: implementation packages
    ├── protocol/              ← Binary frame format (5-byte header + payload)
    ├── auth/                  ← HMAC-SHA256 token generation/verification
    ├── config/                ← YAML config + users file load/save
    ├── ipwhitelist/           ← Per-user CIDR IP allow-list
    ├── smtp/                  ← SMTP handshake (220/EHLO/STARTTLS/AUTH/BINARY)
    ├── certs/                 ← CA + server cert generator (ECDSA P-256)
    ├── tunnel/                ← Multiplexed tunnel (server + client + channels)
    ├── socks5/                ← Local SOCKS5 proxy server
    └── cli/                   ← Subcommand flag parsing & helpers
```

**Why two binaries?**
- `smtp-tunnel-go` is the all-in-one tool that runs on the **server** (VPS).
  It contains every command: `server`, `client`, `gencerts`, `adduser`,
  `deluser`, `listusers`.
- `smtp-tunnel-client` is a thin wrapper that only runs the `client`
  subcommand. It exists so the auto-generated client ZIP package (from
  `adduser`) ships with a single-purpose binary — your users don't need
  to type `smtp-tunnel-go client ...`, they just run it.

**Why `.example` files?**
- `config.yaml.example` and `users.yaml.example` are templates showing
  the format. `install.sh` and `adduser` generate the real files with
  your actual domain name, secrets, etc. You only need the `.example`
  files if you want to set things up manually without `install.sh`.

---

## Three ways to deploy

### Option A — Quick install on a Linux VPS (recommended)

```bash
# 1. Copy install.sh to your VPS, then run:
sudo bash install.sh

# 2. Answer the prompts (domain name, first username)
# 3. Done. The service is running, certs generated, first user created.
```

The installer downloads a prebuilt binary (or builds from source if Go
is available), generates certs for your domain, creates `/etc/smtp-tunnel/`
with config + users + certs, installs a systemd service, and starts it.

### Option B — Manual install using the prebuilt binaries

```bash
# 1. Pick the right binary for your platform from release/
#    e.g. for Linux x86_64:
cp release/smtp-tunnel-go-linux-amd64 /usr/local/bin/smtp-tunnel-go
chmod +x /usr/local/bin/smtp-tunnel-go

# 2. Generate certs
smtp-tunnel-go gencerts --hostname yourdomain.duckdns.org --output-dir /etc/smtp-tunnel

# 3. Create config
cp config.yaml.example /etc/smtp-tunnel/config.yaml
# Edit /etc/smtp-tunnel/config.yaml — set hostname, cert paths, etc.

# 4. Add a user
smtp-tunnel-go adduser alice -c /etc/smtp-tunnel/config.yaml -u /etc/smtp-tunnel/users.yaml -o /root/

# 5. Run the server
smtp-tunnel-go server -c /etc/smtp-tunnel/config.yaml
```

### Option C — Build from source (if you want to modify the code)

```bash
# Requires Go 1.21+ from https://go.dev/dl/
make           # builds bin/smtp-tunnel-go and bin/smtp-tunnel-client
sudo make install
```

---

## On the client side

When you run `smtp-tunnel-go adduser alice`, the script automatically
generates `alice.zip` containing:
- A standalone `smtp-tunnel-client` binary for the server's platform
- A pre-configured `config.yaml` with the user's secret
- The `ca.crt` for TLS verification
- `start.sh` (Linux/macOS) and `start.bat` (Windows) launchers
- A README.txt

Send that ZIP to your user. They extract it and run `./start.sh` (or
`start.bat` on Windows). Their SOCKS5 proxy will be at `127.0.0.1:1080`.

If you need a client binary for a *different* platform than the server
(e.g. server is Linux but user is on Windows), use the appropriate
binary from `release/`:
- `smtp-tunnel-client-windows-amd64.exe` for Windows
- `smtp-tunnel-client-darwin-arm64` for Apple Silicon Mac
- `smtp-tunnel-client-darwin-amd64` for Intel Mac
- `smtp-tunnel-client-linux-arm64` for ARM Linux (e.g. Raspberry Pi 4)

---

## Verifying it works

After starting the client, test with curl:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

Should print your VPS's IP address (not your real IP).

---

## Need more info?

Read `README.md` for full feature list, configuration reference, and
architecture. Read `TECHNICAL.md` for protocol details, DPI evasion
analysis, and security threat model.
