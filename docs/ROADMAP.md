# MyMesh roadmap

Status: **done** · planned · deferred

## Product goal

Before leaving alpha, maintainability gates live in [v0.1-promotion-goals.md](v0.1-promotion-goals.md).


Personal machine mesh: install → link with explicit approval → remote **terminal**, **files**, **SSH/TCP services**, later **desktop**, with NAT traversal and no port forwards.

---

## Releases

### v0.1.0-alpha.1 — **done**

Request/accept join, 24-word ids, iroh, shell, cp, honest docs.

### v0.1.0-alpha.2 — **done**

Install lifecycle, user systemd unit, TUI, mesh gossip, kick, file browser, metrics.

### v0.1.0-alpha.3 — **done** (this tag)

| Item | State |
|------|--------|
| Labels / aliases / groups | **done** |
| Magic DNS + SOCKS + mesh IPs + auto ports | **done** (userspace) |
| SSH ProxyCommand | **done** |
| `expose` + TCP tunnels | **done** |
| Connect-by-carrier | **done** (phone scanner only) |
| Single-endpoint dial proxy | **done** |
| Firewall helper (explicit) | **done** |
| System-wide `*.mym` DNS install | planned |
| ICMP over mesh | not planned (use `mymesh ping`) |

Docs: [ALPHA-3.md](ALPHA-3.md), [USAGE.md](USAGE.md).

### v0.1.0-alpha.4+ — planned

| Item | Notes |
|------|--------|
| Split-DNS / resolv helper for `*.mym` | Optional, distro-aware |
| UX polish pass (TUI) | Including remaining resize chrome |
| Packages | deb, rpm, AUR; one-line curl installer |
| Enable CI | Linux builds on GitHub Actions |
| Web UI / tray | After TUI IA stable |
| Desktop control | Former M4 |
| Carrier Android shim | Phone as temporary node (future) |

### Later / deferred

| Item | Notes |
|------|--------|
| Full TUN VPN | Non-goal near term |
| Multi-account agent policy | User-level default stays |
| Yggdrasil / libp2p core | Rejected for now (iroh stays) |

---

## Historical engineering milestones

| Milestone | Scope | State |
|-----------|--------|--------|
| M0 | Scaffold, SPAKE, protocol | done |
| M1 | iroh, mailboxes, serve | done |
| M2 | Remote PTY | done |
| M3 | File cp | done |
| M-Link | Request/accept join | done |
| M-Mesh | Gossip + kick | done (alpha.2) |
| M-Magic | Names, SSH, SOCKS, carrier | done (alpha.3) |
| M4 | Desktop | deferred |

---

## Non-goals (near term)

- Replacing WireGuard/Tailscale as a full L3 VPN  
- Public multi-tenant relay operated by MyMesh  
- Silent firewall changes  
