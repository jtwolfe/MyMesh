# MyMesh

**Peer-to-peer remote access without port forwards.**

Link your own machines with a one-time approval, then open a remote shell, copy files, SSH, or reach local web services over an encrypted P2P path ([iroh](https://iroh.computer): QUIC, NAT hole punching, relay fallback).

Inspired by **Signal linked devices** (explicit trust) and **Syncthing** (dial by device id, not IP).

| | |
|--|--|
| **Status** | **v0.1.0-alpha.3** — early adopters; CLI may still change |
| **License** | Apache-2.0 OR MIT |
| **Repo** | https://github.com/jtwolfe/MyMesh |

---

## What works (alpha.3)

| Capability | How |
|------------|-----|
| **Link machines** | Arm host → join by id/words → accept once (default). SPAKE local mailbox optional |
| **Device ids** | 64-char hex **or** 24 BIP39 words; QR / join URI |
| **Always-up agent** | `mymesh install` → user systemd unit + dial proxy |
| **Remote shell** | `mymesh shell <peer>` or TUI **Term** |
| **File copy** | `mymesh cp` + TUI dual-pane browser |
| **Mesh roster** | Gossip membership; kick with double confirm + pending delivery |
| **Labels / aliases / groups** | `label`, `alias`, `group`, `hosts`, `resolve` |
| **SSH over mesh** | `ssh-config` + `proxy-ssh` → peer `127.0.0.1:22` |
| **TCP tunnels** | `expose`, magic auto-ports, SOCKS5 for browsers |
| **Userspace DNS** | `127.0.0.1:5353` answers `*.mym` (not system-wide by default) |
| **Connect-by-carrier** | Phone scans QR; phone is **not** a mesh node |
| **Firewall helpers** | Explicit `mymesh firewall …` for ufw/firewalld (never auto-open) |
| **TUI** | Default when you run `mymesh` with no args |

## What does *not* work yet (honest)

| Area | Status |
|------|--------|
| System-wide `ping laptop.mym` | Needs you to wire OS DNS to MyMesh; ICMP not tunneled |
| Full L3 VPN / TUN | Not a goal for alpha.3 |
| Desktop / remote GUI control | Stub only |
| Native GUI / web admin | Not built (TUI is the UI) |
| Android “carrier as mesh node” app | Future |
| Packages (deb/rpm/AUR) + one-line curl installer | Planned |
| CI (Linux) | Workflow present, **disabled** |
| Stable API / CLI freeze | **No** — alpha |

MyMesh is **not** Tailscale/WireGuard and **not** a drop-in public OpenSSH replacement. It is a **personal mesh** for machines you explicitly link.

---

## Requirements

- **Linux** (primary; other OSes untested)
- Rust **1.91+** to build from source
- Outbound internet on both peers for the default path (iroh relays)
- For SSH: **sshd** listening on the remote (`127.0.0.1:22` is enough)
- For browser paths: agent running + SOCKS (or magic ports + DNS)

---

## Build & install

```bash
git clone https://github.com/jtwolfe/MyMesh.git
cd MyMesh
git checkout v0.1.0-alpha.3   # or main
cargo build --release -p mymesh-cli

./target/release/mymesh init --label laptop
./target/release/mymesh install          # ~/.local/bin + user unit + completions
systemctl --user enable --now mymesh.service
systemctl --user status mymesh
mymesh --version
```

Prefer **user install** (no root). Root install prints a strong warning and needs override — see [docs/INSTALL-POLICY.md](docs/INSTALL-POLICY.md).

After install, the agent owns the **single iroh endpoint** and exposes a **local dial proxy** (`$XDG_RUNTIME_DIR/mymesh.sock`). CLI/TUI dial *through* that proxy — do not run a second long-lived `serve` as another user with the same identity.

---

## Quick start

### 1. Init + agent (both machines)

```bash
mymesh init --label desktop   # once per machine
mymesh install
systemctl --user enable --now mymesh
mymesh status
```

### 2. Link (request / accept)

**Host** (already in the mesh / will approve):

```bash
mymesh connect-request allow          # arms joins briefly
mymesh id                             # share hex or 24 words
```

**Joiner:**

```bash
mymesh link '<host-hex-or-24-words>'
```

**Host:**

```bash
mymesh requests list
mymesh requests accept <short-id>
```

### 3. Use the mesh

```bash
mymesh devices
mymesh ping desktop
mymesh shell desktop
mymesh cp ./file desktop:~/file
mymesh                          # TUI
```

### 4. SSH (alpha.3)

```bash
# remote must run sshd; mesh path must work (ping first)
mymesh ssh-config >> ~/.ssh/config
ssh desktop.mym
```

### 5. Web services via SOCKS

```bash
# agent running on this machine
export ALL_PROXY=socks5h://127.0.0.1:18080   # socks5h = resolve *.mym via proxy
curl -v http://laptop.mym:7878/
# or configure browser: SOCKS5 127.0.0.1:18080 + proxy DNS
```

Full command reference: **[docs/USAGE.md](docs/USAGE.md)**  
Magic plane details: **[docs/ALPHA-3.md](docs/ALPHA-3.md)**  
Linking model: **[docs/JOIN.md](docs/JOIN.md)**

---

## Documentation map

| Doc | Contents |
|-----|----------|
| **[docs/REWORK-UNIFY.md](docs/REWORK-UNIFY.md)** | Design: unify carrier + MyMesh |
| **[docs/USAGE.md](docs/USAGE.md)** | Comprehensive CLI + TUI + SSH + SOCKS + ops |
| [docs/ALPHA-3.md](docs/ALPHA-3.md) | Magic plane design & limits |
| [docs/JOIN.md](docs/JOIN.md) | Arming, ids, carrier, SPAKE, pair v1→v2 migration |
| [docs/PAIR-V2.md](docs/PAIR-V2.md) | S0: pair v2 wire, nonce, confirm 4-4, not_bound |
| [docs/DEMO-PAIR.md](docs/DEMO-PAIR.md) | Wave A E2E: dual-scan+confirm; mock-pair-host lab-only |
| [docs/MASTER-KEY.md](docs/MASTER-KEY.md) | S0: mesh master key / policy root |
| [docs/RECOVERY.md](docs/RECOVERY.md) | Dual-authority recovery runbooks (lost phone/MMK, guest, rotate, backup) |
| [docs/GRANTS.md](docs/GRANTS.md) | S0: grant schema |
| [docs/GUEST.md](docs/GUEST.md) | S0: guest membership (no full roster) |
| [docs/CARRIER-NEXT.md](docs/CARRIER-NEXT.md) | S0–S9 design (MyMesh + Carrier next phase) |
| [docs/SECURITY.md](docs/SECURITY.md) | Operator security model (alpha) |
| [docs/THREATS.md](docs/THREATS.md) | Threat catalog + S9 control checklist C1–C7 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Crate layout, endpoint ownership |
| [docs/INSTALL-POLICY.md](docs/INSTALL-POLICY.md) | User vs root install |
| [docs/ROADMAP.md](docs/ROADMAP.md) | What’s next |
| [docs/v0.1-promotion-goals.md](docs/v0.1-promotion-goals.md) | Maintainability gates before non-alpha v0.1 |
| [CHANGELOG.md](CHANGELOG.md) | Release notes |
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | Frame notes |
| [docs/M1-M3.md](docs/M1-M3.md) | Early milestone design |

---

## Project layout

```text
crates/
  mymesh-cli       CLI + TUI binary (`mymesh`)
  mymesh-core      config, devices, mesh state, paths
  mymesh-crypto    identity, SPAKE2, 24-word ids
  mymesh-protocol  frames + messages
  mymesh-net       iroh transport, dial proxy, mailboxes
  mymesh-session   join, agent, mesh sync, magic, carrier, TCP tunnel
  mymesh-terminal  PTY host/client
  mymesh-files     sandboxed transfer
  mymesh-desktop   stub (deferred)
```

---

## Security (alpha, short)

- **Default closed:** joins fail unless the host is **armed**
- **Trust = allowlist:** only `Trusted` peers get shell/files/TCP
- **Agent runs as the installing user** (user unit default)
- **Files** sandboxed (default: home)
- A compromised linked peer with Terminal+Files is powerful — unlink / kick promptly
- Firewall helper is **explicit only**; never opens ports by itself

Threat model and S9 controls **C1–C7** (session fixation, wrong joiner, backup theft, guest residual, topology MITM, facet bleed, decide rate limits): **[docs/THREATS.md](docs/THREATS.md)** · operator notes: **[docs/SECURITY.md](docs/SECURITY.md)**

---

## Roadmap snapshot

| Release | Focus |
|---------|--------|
| **v0.1.0-alpha.1** | Link + shell + cp |
| **v0.1.0-alpha.2** | Install, TUI, mesh gossip, kick |
| **v0.1.0-alpha.3** | Magic names, SSH, SOCKS, carrier, labels (**this**) |
| Later | System DNS helper, packages, GUI, desktop, CI |

---

## Contributing / feedback

Alpha: expect breakage. Issues and PRs welcome.

## License

Dual-licensed under **Apache-2.0** OR **MIT**.
