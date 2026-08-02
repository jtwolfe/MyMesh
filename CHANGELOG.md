# Changelog

All notable releases are documented here. Format inspired by [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0-alpha.1] — 2026-08-02

First tagged alpha. Suitable for early self-host testing on Linux. **Not** production-hardened.

### Added

- Request/accept device linking:
  - `mymesh connect-request allow|deny|status`
  - `mymesh link <device-id>`
  - `mymesh requests list|accept|deny`
  - Auto-disarm after successful accept
- Device identity display:
  - 64-char hex id
  - 24-word BIP39 encoding (`mymesh id`, `--words`, `--uri`)
  - URI scheme `mymesh:v1:join:<hex>` (QR-ready payload)
- Agent: `mymesh serve` (trusted sessions + join handling when armed)
- Remote terminal: `mymesh shell`
- File transfer: `mymesh cp` (sandboxed)
- iroh-based P2P transport (hole punch + relay)
- Advanced SPAKE pairing (`--local`, `--mailbox-dir`, `--code`, HTTP mailbox)
- Docs: README, JOIN, ROADMAP, SECURITY, INSTALL-POLICY

### Known limitations

- No systemd installer; `serve` is a foreground/manual process
- No TUI (CLI only)
- No desktop remote control
- No `*.mym` DNS / stock OpenSSH integration
- CI workflow present but disabled
- CLI and on-disk formats may change before 0.1.0

### Security notes

- Joins rejected unless host is armed
- Agent privilege = OS user running `serve`
- File access limited to sandbox root (default home)

## [Unreleased]

Work targeting **v0.1.0-alpha.2**: install lifecycle, user systemd unit, TUI, peer metrics.

[0.1.0-alpha.1]: https://github.com/jtwolfe/MyMesh/releases/tag/v0.1.0-alpha.1
