# MyMesh

**Peer-to-peer remote access without port forwards.**

Link your own machines with a one-time approval, then open a remote shell or copy files over an encrypted P2P path ([iroh](https://iroh.computer): QUIC, NAT hole punching, relay fallback).

Inspired by **Signal linked devices** (explicit trust) and **Syncthing** (dial by device id, not IP).

| | |
|--|--|
| **Status** | **v0.1.0-alpha.1** — usable for early adopters; CLI and APIs may change |
| **License** | Apache-2.0 OR MIT |
| **Repo** | https://github.com/jtwolfe/MyMesh |

---

## What works today (alpha.1)

- **Request / accept linking** — host arms joins, joiner dials by device id, host accepts once; arm auto-disarms
- **Device ids** — 64-char hex **or** 24 BIP39 English words (full key material)
- **Agent** — `mymesh serve` accepts sessions from trusted peers only
- **Remote terminal** — `mymesh shell <label|id>` (real PTY)
- **File copy** — `mymesh cp` push/pull with path sandbox (default: home)
- **WAN path** — iroh dial-by-public-key; works across networks when both have outbound internet
- **Advanced pairing** — SPAKE short codes + local/HTTP mailbox (optional)

## What does *not* work yet (honest)

| Area | Status |
|------|--------|
| Desktop / remote GUI | Deferred |
| Systemd install / `systemctl status mymesh` | Planned (alpha.2) |
| Default TUI | Planned (alpha.2) |
| Magic names (`ssh host.mym`) | Planned later |
| Polished one-line installer + deb/rpm/AUR | Planned later |
| QR scan / native GUI / web UI | Not built (URI ready for QR tools) |
| Multi-user “run shell as other account” | Not built |
| CI (Linux) | Workflow present, **disabled** |
| Stable API / CLI freeze | **No** — alpha |

MyMesh is **not** a full VPN, not Tailscale, and not a replacement for OpenSSH on the public internet without care. It is a **personal mesh** for machines you explicitly link.

---

## Requirements

- Linux (primary target; other OSes untested in alpha)
- Rust toolchain to build from source (`rustc` 1.91+ per workspace)
- Outbound internet on both peers for the default path (iroh public relays)

---

## Build

```bash
git clone https://github.com/jtwolfe/MyMesh.git
cd MyMesh
git checkout v0.1.0-alpha.1   # or main
cargo build --release -p mymesh-cli
./target/release/mymesh --version
```

Optional helper: [`install.sh`](install.sh) (builds from source; not a full service installer yet).

---

## Quick start (default link path)

Run **`serve` on both machines** and keep it running while you work.

```bash
# both machines
./target/release/mymesh init --label desktop    # or laptop
./target/release/mymesh serve --foreground
```

**On the host** (machine that already “owns” the mesh / will approve):

```bash
./target/release/mymesh connect-request allow
./target/release/mymesh id          # share hex or 24-word id with the joiner
```

**On the joiner:**

```bash
./target/release/mymesh link '<host-hex-or-24-words>'
# waits until the host accepts
```

**On the host:**

```bash
./target/release/mymesh requests list
./target/release/mymesh requests accept <short-id>
# arm turns off automatically after accept
```

**Either side (after link):**

```bash
./target/release/mymesh devices
./target/release/mymesh shell <label-or-id>
./target/release/mymesh cp ./file peer:~/file
./target/release/mymesh cp peer:~/file ./file
```

Details: [docs/JOIN.md](docs/JOIN.md).

### Security notes (alpha)

- **Default closed:** join requests fail unless the host is **armed** (`connect-request allow`).
- **Trust is the allowlist:** only `Trusted` devices get shell/files.
- **Agent runs as the OS user that starts `serve`** (today: manual process; no root service yet).
- **Files** are limited to the configured sandbox (default: your home directory).
- **Do not** treat a linked device as harmless: a compromised peer with Terminal+Files is powerful on your account.

---

## Advanced pairing (optional)

Shared-folder or SPAKE short codes (labs / airgap experiments):

```bash
./target/release/mymesh link --local              # host side SPAKE + auto local mailbox
./target/release/mymesh link --code CODE --local  # guest
# or --mailbox-dir /path or MYMESH_MAILBOX=http://...
```

This is **not** the recommended default for two machines on the internet.

---

## Documentation

| Doc | Contents |
|-----|----------|
| [docs/JOIN.md](docs/JOIN.md) | Linking model, arming, ids |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Milestones, alpha.2 plan |
| [CHANGELOG.md](CHANGELOG.md) | Release notes |
| [docs/M1-M3.md](docs/M1-M3.md) | Transport / shell / files design notes |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Crate layout |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model (alpha) |
| [docs/INSTALL-POLICY.md](docs/INSTALL-POLICY.md) | Future install defaults (user vs system) |
| [docs/RELEASE-HANDOFF.md](docs/RELEASE-HANDOFF.md) | If tag/release needs a local follow-up |

---

## Project layout

```text
crates/
  mymesh-cli       CLI binary
  mymesh-core      config, devices, join arming
  mymesh-crypto    identity, SPAKE2, 24-word ids
  mymesh-protocol  frames + messages
  mymesh-net       iroh transport, mailboxes
  mymesh-session   pair, join, session, agent
  mymesh-terminal  PTY host/client
  mymesh-files     sandboxed transfer
  mymesh-desktop   stub (deferred)
```

---

## Roadmap snapshot

| Release | Focus |
|---------|--------|
| **v0.1.0-alpha.1** | Link + shell + cp (this release) |
| **v0.1.0-alpha.2** | install/uninstall/reset, user systemd unit, TUI default, peer metrics |
| Later | `.mym` names, packages (deb/rpm/AUR), web/GUI, desktop |

---

## Contributing / feedback

Alpha: expect breakage. Issues and PRs welcome on GitHub.

## License

Dual-licensed under **Apache-2.0** OR **MIT**.
