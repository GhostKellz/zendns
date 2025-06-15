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
# Multiple blocklist sources (URLs or local files)
blocklist_sources = [
    "https://someonewhocares.org/hosts/zero/hosts",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt",
    "/etc/zendns/custom_blocklist.txt"
]

# Network configuration
listen_addr = "127.0.0.1:53"    # UDP DNS server
dot_listen_addr = "127.0.0.1:853"  # DNS-over-TLS server  
doh_listen_addr = "127.0.0.1:8443" # DNS-over-HTTPS server
upstream_addr = "1.1.1.1:53"

# TLS configuration for DoT/DoH (required if enabling these protocols)
tls_cert = "/etc/zendns/cert.pem"
tls_key = "/etc/zendns/key.pem"

# Protocol configuration (all optional, defaults shown)
enable_udp = true   # Fast, unencrypted DNS
enable_dot = false  # DNS-over-TLS (requires tls_cert/tls_key)  
enable_doh = false  # DNS-over-HTTPS (requires tls_cert/tls_key)
```

- `blocklist_sources`: Array of URLs or file paths to merge as blocklists
- `listen_addr`: Address/port to bind UDP DNS server to
- `dot_listen_addr`: Address/port to bind DoT server to (default: 127.0.0.1:853)
- `doh_listen_addr`: Address/port to bind DoH server to (default: 127.0.0.1:8443)
- `upstream_addr`: Upstream DNS server for query forwarding
- `tls_cert`, `tls_key`: PEM files for DoT/DoH TLS termination
- `enable_udp`, `enable_dot`, `enable_doh`: Protocol toggles

### Blocklist File (blocklist.toml)
```toml
# Local and remote blocklists
local = ["/etc/hosts", "/etc/zendns/ads.txt"]
remote = [
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
  "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt",
  "https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt",
  "https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt",
  "https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt"
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
