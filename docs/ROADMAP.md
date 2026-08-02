# MyMesh roadmap

Status: **done** · planned · deferred

## Product goal

Personal machine mesh: install → link with explicit approval → remote **terminal**, **files**, later **desktop**, with NAT traversal and no port forwards.

---

## Releases

### v0.1.0-alpha.1 — **done** (gate)

| Item | State |
|------|--------|
| Request/accept join + arm/auto-disarm | done |
| 24-word + hex device ids | done |
| iroh transport, `serve`, `shell`, `cp` | done |
| Honest docs + changelog + tag | done |
| Real multi-machine validation | done (maintainer) |

### v0.1.0-alpha.2 — **done**

| Item | Notes |
|------|--------|
| `install` / `uninstall` / `reset` | **done** |
| User systemd unit (default) | **done** |
| System install | **done** |
| Shell completions | **done** (bash/zsh/fish) |
| TUI default (`mymesh` with no args) | **done** (shell via CLI from TUI in this cut) |
| Peer status | **done** |
| Word-id paste polish | **done** |

Install policy (user default, root override): [INSTALL-POLICY.md](INSTALL-POLICY.md).

### v0.1.0-alpha.3+ — planned

| Item | Notes |
|------|--------|
| TUI embedded shell/cp | Full session inside TUI |
| Auto peer probe loop | Background 60s sampler while TUI/agent runs |
| Packages / curl installer | deb rpm AUR |

### Later

| Item | Notes |
|------|--------|
| `.mym` hostnames | Default suffix configurable; SSH ProxyCommand / local map |
| Packages | deb, rpm, AUR; one-line curl installer page |
| Web UI / tray GUI | After TUI IA is stable |
| Desktop control | Former M4 |
| Enable CI | Linux builds on GitHub Actions |
| Multi-account agent | Not root + su; policy engine if ever |

---

## Historical milestones (engineering)

| Milestone | Scope | State |
|-----------|--------|--------|
| M0 | Scaffold, SPAKE, protocol, demos | done |
| M1 | iroh, mailboxes, serve | done |
| M2 | Remote PTY | done |
| M3 | File cp | done |
| M-Link | Request/accept default join | done (alpha.1) |
| M4 | Desktop | deferred |

Design notes: [M1-M3.md](M1-M3.md).

---

## Non-goals (near term)

- Replacing WireGuard/Tailscale as a full L3 VPN
- Public multi-tenant relay operated by MyMesh (rely on iroh defaults for now)
- Yggdrasil / libp2p as core transport
