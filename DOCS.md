# zendns Documentation

## Installation

### Prerequisites
- Rust (latest stable, install via [rustup](https://rustup.rs/))
- Arch Linux (recommended, but portable)

### Build & Install
```sh
cargo build --release
sudo cp ./target/release/zendns /usr/local/bin/
```

### Initial Setup
```sh
mkdir -p ~/.config/zendns
cp example.config.toml ~/.config/zendns/config.toml
# (Optional) Add root.key and blocklist.toml as needed
```

## Configuration

zendns is configured via a TOML file at `~/.config/zendns/config.toml`.

### Example config.toml
```toml
listen_addr = "127.0.0.1:53"
upstream_addr = "1.1.1.1:53"
blocklist_file = "/etc/zendns/blocklist.toml"
# tls_cert = "/etc/zendns/cert.pem"
# tls_key = "/etc/zendns/key.pem"
```

- `listen_addr`: Address/port to listen on (UDP/DoT/DoH)
- `upstream_addr`: Upstream DNS server (for recursion/forwarding)
- `blocklist_file`: Path to blocklist config (local + remote URLs)
- `tls_cert`, `tls_key`: (Optional) PEM files for DoT/DoH

### Blocklist File (blocklist.toml)
```toml
# Local and remote blocklists
local = ["/etc/hosts", "/etc/zendns/ads.txt"]
remote = [
  "https://blocklistproject.github.io/Lists/ads.txt",
  "https://someonewhocares.org/hosts/hosts"
]
```

- All domains are merged and reloaded on SIGHUP.

### Root Trust Anchors
- Place your root.key file at `~/.config/zendns/root.key` (format: one DNSKEY per line)
- Root hints auto-updated from internic

## Running
```sh
zendns
```
- Logs to stdout by default
- Reload config/blocklists with `kill -SIGHUP <pid>`

## Advanced
- Supports DNS-over-UDP, DoT, DoH (auto-enabled if TLS config present)
- Fully async, lock-free cache (DashMap)
- DNSSEC validation (with root trust anchors)
- Blocklist auto-merge (local + remote)
- Hot reloads (SIGHUP)

## Troubleshooting
- Check logs for errors (permissions, port conflicts, config parse errors)
- Ensure `root.key` and `blocklist.toml` are readable by the zendns process
- For DoT/DoH, ensure valid TLS cert/key are configured

## See Also
- [Unbound](https://nlnetlabs.nl/projects/unbound/about/)
- [Blocky](https://github.com/0xERR0R/blocky)
- [cloudflared](https://github.com/cloudflare/cloudflared)
