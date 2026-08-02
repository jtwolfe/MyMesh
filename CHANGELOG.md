# Changelog

## [0.1.0-alpha.2] — 2026-08-02

### Added

- **Lifecycle:** `mymesh install` / `uninstall` / `reset`
  - Default **user** systemd unit (`~/.config/systemd/user/mymesh.service`)
  - Binary to `~/.local/bin/mymesh`
  - **System** install (`--system`) requires root, prefers runtime user `mymesh`, refuses root agent without `--i-accept-root-agent`
- **Service control:** `mymesh service status|start|stop|restart` (`systemctl [--user]`)
- **Completions:** `mymesh completions bash|zsh|fish` (also installed by `install`)
- **TUI (default):** bare `mymesh` opens dashboard (tabs: Dashboard, Peers, Link, Tools, Service)
  - Arm/disarm, accept pending, peer list + RTT history, bandwidth test, service toggle, QR
- **Peer metrics:** `mymesh ping`, `mymesh bw`, `mymesh probe-all`; ~60 sample history on disk
- **Agent:** responds to control `Ping` with `Pong`
- **Word-id paste:** numbered lists, commas, URI prefix, quotes tolerated

### Changed

- Workspace version `0.1.0-alpha.2`
- Bare `mymesh` prefers TUI when stdin is a TTY (`--no-tui` for help)

### Notes

- System install needs a real systemd host; containers without systemctl will fail system mode (expected)
- Shell/cp from TUI still guided to CLI for full sessions in this alpha

## [0.1.0-alpha.1] — 2026-08-02

First tagged alpha: request/accept join, shell, cp, iroh. See git history.

[0.1.0-alpha.2]: https://github.com/jtwolfe/MyMesh/releases/tag/v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/jtwolfe/MyMesh/releases/tag/v0.1.0-alpha.1
