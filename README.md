# MyMesh

**Peer-to-peer remote access for people who hate port forwards.**

Pair two machines with a short code (Signal linked-devices style). After that you get:

- **Remote terminal** (real PTY — WAN path in progress)
- **File copy** (chunked, sandboxed — WAN path in progress)
- **Desktop control** (capture + input; platform backends feature-gated)

NAT hole punching + relay fallback is designed around [iroh](https://iroh.computer) (QUIC, dial by public key). The workspace builds today with a **local fabric** for demos and tests; the production transport plugs in behind the `Transport` trait.

## Status

| Milestone | Scope | State |
|-----------|--------|--------|
| **M0** | Scaffold, SPAKE2 pairing demo, protocol, local fabric, CLI, install script, CI (disabled) | **done** |
| M1 | iroh transport, mailbox rendezvous, real `mymesh link` over WAN | next |
| M2 | PTY shell end-to-end over iroh | planned |
| M3 | File cp/get/put + progress | planned |
| M4 | Desktop capture backends (X11 / Wayland portal) | planned |
| M5 | Packaging, signed releases, enable CI | planned |

## Quick start

```bash
# install from source (Linux)
curl -fsSL https://raw.githubusercontent.com/jtwolfe/MyMesh/main/install.sh | bash

# or build locally
cargo build --release -p mymesh-cli
./target/release/mymesh init
./target/release/mymesh status
./target/release/mymesh demo pair
./target/release/mymesh demo session
```

## CLI

```text
mymesh init                 # create identity + config
mymesh status               # show device id + fingerprint
mymesh link                 # host: print pairing code (WAN: M1)
mymesh link 42-maple-orbit  # guest: enter code (WAN: M1)
mymesh devices              # list linked devices
mymesh unlink <id>          # revoke a device
mymesh shell <device>       # remote terminal (WAN: M2)
mymesh cp <src> <dst>       # file copy (WAN: M3)
mymesh desktop <device>     # remote desktop (WAN: M4)
mymesh serve --foreground   # agent process
mymesh demo pair            # in-process SPAKE2 ceremony
mymesh demo session         # pair + framed terminal open
mymesh install-notes        # systemd unit hints
```

## Workspace layout

```text
crates/
  mymesh-core       identity, config, device store
  mymesh-crypto     Ed25519 identity, SPAKE2, pairing codes
  mymesh-protocol   frames + control/terminal/files/desktop messages
  mymesh-net        Transport trait, local fabric, directional rendezvous
  mymesh-session    pairing ceremony + session handshake
  mymesh-terminal   portable-pty host + client
  mymesh-files      sandboxed transfers
  mymesh-desktop    desktop controller (null + future capture)
  mymesh-cli        `mymesh` binary
docs/
  RESEARCH.md       library survey & decisions
  ARCHITECTURE.md   system design
  PROTOCOL.md       wire format
install.sh          Linux from-source installer
.github/workflows/ci.yml   Linux CI (currently disabled)
```

## Security model

1. **Pairing** uses SPAKE2 so a short code becomes a strong shared secret.
2. **Long-term** Ed25519 identities are exchanged under that secret and stored as linked devices.
3. **Sessions** only accept peers present in the local device store with required capabilities.
4. **Files** never escape a configured sandbox root.
5. **Transport** (iroh, planned) provides authenticated encryption on the wire (QUIC).

## CI

GitHub Actions workflow exists at [`.github/workflows/ci.yml`](.github/workflows/ci.yml) for Linux (`fmt`, `clippy`, `test`, release build, smoke). **It is disabled** (`if: false`, no push/PR triggers). Enable when ready by removing the gate and uncommenting triggers.

## License

Apache-2.0 OR MIT
