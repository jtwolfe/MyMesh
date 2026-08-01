# MyMesh — research & library decisions

## Problem

Build a **professional**, install-simple, **NAT-punching P2P** remote access tool in Rust:

| Need | Notes |
|------|--------|
| Pairing UX | Signal “linked devices” / magic-wormhole short codes |
| Transport | Works behind CGNAT/home routers without manual port maps |
| Terminal | Full interactive PTY, resize, colors |
| Files | cp/rsync-like, resume, safe paths |
| Desktop | View + control (Wayland/X11/macOS/Windows) |
| Ops | Single binary, systemd service, minimal knobs |

## Transport candidates

| Option | Pros | Cons | Verdict |
|--------|------|------|---------|
| **iroh** (n0) | Dial by public key; QUIC; hole punch + public relays; production 1.x; excellent Rust API | Relay trust / availability; dependency weight | **Primary production transport** |
| **quinn** alone | Full control | You rebuild discovery, hole punch, relays | Too much undifferentiated work |
| **rust-libp2p** | Flexible swarm | Complex; NAT story weaker out of the box for “pair two laptops” | Not default |
| **boringtun / WireGuard userspace** | VPN-grade tunnel | Key distribution & NAT still hard; not app-multiplex friendly | Optional future “full L3 mode” |
| **WebRTC (webrtc-rs)** | Browser interop | Heavier; media-centric | Desktop media path only if needed |

**Decision:** `Transport` trait in `mymesh-net`, production impl = **iroh** (`Endpoint::bind`, `connect(EndpointAddr)`, bi-streams, ALPN `mymesh/1`). Local fabric for tests.

### Why iroh over reinventing Tailscale/WireGuard

Tailscale-class UX needs a coordination plane + DERP-like relays + key distribution. iroh already ships that composition with a library-first Rust API (“dial keys, not IPs”). We stay an **application** on QUIC streams rather than a system-wide VPN (simpler install, clearer security boundary).

## Pairing / crypto

| Piece | Crate | Role |
|-------|-------|------|
| PAKE | `spake2` | Short code → strong secret |
| Identity | `ed25519-dalek` | Long-term device keys; device id = pubkey |
| KDF | `hkdf` + `sha2` | Session confirm keys, binders |
| Codes | custom wordlist | `N-word-word` human codes |
| Zeroize | `zeroize` | Wipe secrets |

Alternatives considered: full `magic-wormhole` crate (heavier, Python-interop focus); Noise `snow` (great for session transport, less ideal for short-code PAKE UX). SPAKE2 matches the product story exactly.

## Terminal

| Crate | Role |
|-------|------|
| `portable-pty` | Cross-platform PTY (wezterm) |
| `crossterm` | Client raw mode / resize hooks |

## Files

Custom protocol on multiplexed streams (see PROTOCOL.md). No need for SSH/SFTP stack. Sandbox path resolver prevents `../` escapes.

## Desktop

| Layer | Libraries |
|-------|-----------|
| Capture Linux X11 | `xcap`, XShm |
| Capture Wayland | PipeWire + xdg-desktop-portal (`lamco-wayland` / portal crates) |
| Capture macOS/Win | `xcap` / DXGI |
| Encode | `vpx-encode`, `rav1e`, or hardware |
| Input | `enigo`, Linux `uinput` for Wayland unattended |

**Decision:** ship controller + null capture first; feature-gate real backends. Omarchy/Hyprland path should prefer portal + PipeWire and document seat permissions.

## Async / CLI / UX

- `tokio` runtime
- `clap` derive CLI
- `tracing` logs
- `console` / `indicatif` for human output
- `directories` for XDG paths

## Competitive landscape (not dependencies)

| Product | Gap we fill |
|---------|-------------|
| Tailscale + ssh/wayvnc | Great net, but multi-tool; account-centric |
| ZeroTier | Network ID join, not Signal-like PAKE |
| RustDesk | Strong desktop; less “unix tools” feel; ID servers |
| Magic Wormhole | Files only |
| SSH | No NAT miracle without jump hosts |

MyMesh = **wormhole pairing + iroh fabric + ssh/scp/rdp feature set** in one Rust agent.

## Risks

1. Wayland unattended control is politically/technically hard — document portal prompts.
2. Public relays see metadata (who dials whom), not payload (QUIC). Offer self-hosted relay later.
3. Short codes are guessable if TTL/rate limits weak — enforce short TTL + attempt limits on mailbox.
