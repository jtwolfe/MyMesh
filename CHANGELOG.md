# Changelog

All notable changes to MyMesh are documented here. Versions follow `0.1.0-alpha.N`.

## [0.1.0-alpha.3] — 2026-08-02

Focus: names, SSH, TCP tunnels, SOCKS, DNS, carrier join, dial proxy.

### Added
- Labels, aliases, groups + `hosts` / `resolve`
- Magic plane on `serve`: userspace DNS (`*.mym`), SOCKS5, `127.64/16` mesh IPs, auto port forwards
- SSH via OpenSSH ProxyCommand (`ssh-config`, `proxy-ssh` → peer `:22`)
- `expose` local TCP listener → peer port
- Connect-by-carrier (phone QR page; phone is not a mesh node)
- Reconnect probes + systemd `Restart=always` install unit
- Firewall helpers: `firewall explain|status|ufw|firewalld` (explicit only)
- Local **dial proxy** so CLI/TUI share the agent’s single iroh endpoint
- TUI: carrier, link, unlink, requests, names, expose, firewall, magic/ssh helpers

### Fixed
- Multi-bind iroh identity collision (session `connection lost` / connect timeouts)
- TCP/SSH tunnel full-duplex deadlock (proxy-ssh hang after dial)
- Bandwidth decode of control frames as file messages
- Remote shell Ctrl+D no longer bricks the TUI
- Completions coverage; clap `firewall help` → `explain`
- OpenSSH ProxyCommand without `XDG_RUNTIME_DIR` finds control socket

### Known limitations
- System-wide DNS for `*.mym` not auto-configured; ICMP `ping host.mym` not supported
- Hyprland fullscreen TUI chrome still imperfect
- Desktop control still stub; no deb/rpm/AUR yet
- CLI surface may still change before beta

## [0.1.0-alpha.2] — 2026-08

- Mesh gossip / shared membership, remote kick + pending delivery
- TUI default, file browser, shell pane, peer metrics
- Install / uninstall / reset, user systemd unit, completions
- Word ids, probe bandwidth/latency history

## [0.1.0-alpha.1] — 2026-08

- Request/accept join, 24-word ids, iroh transport
- `serve`, `shell`, `cp`, SPAKE optional path
- Initial docs and release tag
