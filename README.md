# zendns

![DoT/DoH Secure](https://img.shields.io/badge/DoT%2FDoH-Secure-blueviolet)
![Cloudflare DNS Ready](https://img.shields.io/badge/Cloudflare%20DNS-Ready-orange)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/ghostkellz/zendns/ci.yml?branch=main)](https://github.com/ghostkellz/zendns/actions)


A blazing fast, async, DNS-over-UDP/DoT/DoH resolver for Arch Linux workstations, with:
- **DNSSEC** validation (secure by default)
- **Root hints** auto-updating
- **Blocklists** for ad/malware/tracker blocking (Blocky/Unbound style)
- **Concurrent cache** (DashMap, lock-free)
- **Hot reloads** (SIGHUP)
- **Modern Rust async** (tokio, hyper, trust-dns)

## Features
- DNSSEC validation (with root trust anchors)
- Root hints auto-download and update
- Blocklist support (local files + remote URLs, auto-merge)
- DNS-over-UDP, DNS-over-TLS (DoT), DNS-over-HTTPS (DoH)
- High-performance async cache with TTL
- Graceful reloads (SIGHUP)
- Designed for Arch Linux, but portable

## Quick Start
```sh
cargo build --release
cp ./target/release/zendns /usr/local/bin/
mkdir -p ~/.config/zendns
cp example.config.toml ~/.config/zendns/config.toml
zendns
```

## Configuration
See [DOCS.md](./DOCS.md) for full details. Example:
```toml
listen_addr = "127.0.0.1:53"      # UDP DNS server
dot_listen_addr = "127.0.0.1:853" # DoT server  
doh_listen_addr = "127.0.0.1:8443" # DoH server
upstream_addr = "1.1.1.1:53"
blocklist_sources = ["https://someonewhocares.org/hosts/zero/hosts"]
# tls_cert = "/etc/zendns/cert.pem"
# tls_key = "/etc/zendns/key.pem"
```

## Blocklists
- Supports local and remote blocklists (see blocklist.toml)
- Auto-merges and reloads on SIGHUP

## DNSSEC & Root Hints
- Root trust anchors loaded from `~/.config/zendns/root.key`
- Root hints auto-updated from internic

## Performance
- Fully async, lock-free cache (DashMap)
- Handles thousands of concurrent queries
- Designed for low-latency on modern workstations

## Roadmap
- DNS-over-QUIC (DoQ)
- Per-client policies
- Prometheus metrics
- Web dashboard


---

See [DOCS.md](./DOCS.md) for install/configuration instructions.
