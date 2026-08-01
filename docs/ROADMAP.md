# MyMesh roadmap

Status legend: **done** · **in progress** · planned · deferred

## Product goal

Signal-style linked devices for machines: install → pair with a short code →
remote **terminal**, **files**, and later **desktop**, with NAT traversal and
no port forwards.

---

## M0 — Foundation — **done**

- Workspace crates, Ed25519 identity, SPAKE2 pairing codes
- Wire protocol (frames + control/terminal/files/desktop messages)
- Local fabric + in-process demos (`mymesh demo pair|session`)
- CLI skeleton, `install.sh`, disabled Linux CI

## M1 — Real link + agent — **in progress / this branch**

**Goal:** two processes (same host or WAN) pair with a code and stay linked;
agent accepts authenticated sessions.

| Work item | Detail |
|-----------|--------|
| Iroh transport | Dial-by-public-key QUIC, hole punch + n0 relays (`Transport` impl) |
| Shared identity | Long-term Ed25519 key **is** the iroh `SecretKey` / `EndpointId` |
| Pairing mailbox | HTTP mailbox (`mymesh mailbox`) + filesystem mailbox for local multiproc |
| `mymesh link` | Host prints code; guest enters code; both persist `DeviceRecord` |
| `mymesh serve` | Bind iroh endpoint, accept only trusted peers, session handshake |
| Endpoint hints | Optional serialized peer addr JSON on the device record |

**Exit criteria**

- [x] `mymesh link` + `mymesh link <code>` across two processes (FS or HTTP mailbox)
- [x] Both sides list each other in `mymesh devices`
- [x] `mymesh serve` accepts connections from linked peers only
- [ ] Two laptops on different NATs (validation on real networks)

## M2 — Remote terminal — **in progress / this branch**

**Goal:** `mymesh shell <device>` opens an interactive PTY on the peer.

| Work item | Detail |
|-----------|--------|
| Host PTY | `portable-pty` already in `mymesh-terminal` |
| Agent demux | Serve loop routes terminal channel frames to PTY host |
| Client | Raw mode, stdin → Input, Output → stdout, resize, exit |
| Caps | Require `Capability::Terminal` on the peer record |

**Exit criteria**

- [x] Interactive shell over live transport (local multiproc / iroh)
- [x] Clean exit + remote process teardown
- [ ] Daily-drive validation on Omarchy box

## M3 — File copy — **in progress / this branch**

**Goal:** `mymesh cp` push/pull with sandboxing and progress.

| Work item | Detail |
|-----------|--------|
| Path syntax | `device:path` vs local path |
| Host engine | `mymesh-files` Get/Put/Chunk with path sandbox |
| Client | Progress bar (indicatif), chunked transfer |
| Caps | Require `Capability::Files` |

**Exit criteria**

- [x] Push and pull files between linked peers
- [x] Path escape attempts rejected
- [ ] Large-file soak on real WAN

## M4 — Desktop — **deferred (after validation)**

Native capture (X11 / Wayland portal) and input injection. Until then:

- Prefer tunneling existing tools (e.g. wayvnc) over MyMesh once M1–M3 are solid
- `mymesh desktop` remains a stub / null capture

## M5 — Packaging — planned

- Enable CI, signed release binaries, `install.sh` binary mode
- systemd user unit install helper
- Optional AUR / deb

---

## Suggested validation sequence

1. Two shells, shared FS mailbox: pair → serve → shell → cp  
2. HTTP mailbox on LAN  
3. Two NATs (home + phone hotspot) with default iroh relays  
4. Only then schedule M4

## Non-goals (for now)

- Full mesh routing / multi-hop
- TUN/VPN data plane
- Mobile clients
- GUI / tray app
