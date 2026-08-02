# MyMesh

**Peer-to-peer remote access for people who hate port forwards.**

Pair two machines with a short code (Signal linked-devices style). After that:

- **Remote terminal** (real PTY over iroh)
- **File copy** (chunked, sandboxed)
- **Desktop** — deferred to M4 after validation

NAT hole punching + relay fallback via [iroh](https://iroh.computer) (QUIC, dial by public key).


## Link two machines (default)

```bash
# both
cargo build --release -p mymesh-cli
./target/release/mymesh init --label desktop   # or laptop
./target/release/mymesh serve --foreground     # keep running

# on host (existing machine)
./target/release/mymesh connect-request allow
./target/release/mymesh id                     # share hex or 24 words

# on joiner
./target/release/mymesh link <host-hex-or-24-words>

# on host
./target/release/mymesh requests list
./target/release/mymesh requests accept <short-id>
# arm auto-disables after accept

./target/release/mymesh shell <label>
./target/release/mymesh cp ./file peer:~/file
```

Device ids are **64-char hex** or **24 BIP39 words** (full entropy). See [docs/JOIN.md](docs/JOIN.md).

SPAKE / shared-folder pairing remains available as advanced (`--local`, `--mailbox-dir`, `--code`).

## Status

| Milestone | Scope | State |
|-----------|--------|--------|
| **M0** | Scaffold, SPAKE2, protocol, local fabric | **done** |
| **M1** | iroh transport, FS/HTTP mailbox, `link`, `serve` | **done** |
| **M2** | Remote PTY shell | **done** |
| **M3** | File cp push/pull + progress | **done** |
| **M4** | Desktop capture | deferred |
| **M5** | Packaging / enable CI | planned |

See [docs/ROADMAP.md](docs/ROADMAP.md) and [docs/M1-M3.md](docs/M1-M3.md).

## Quick start

```bash
# build
cargo build --release -p mymesh-cli

# machine A
./target/release/mymesh init --label desktop
./target/release/mymesh link --mailbox-dir /shared/mymesh-mb   # or MYMESH_MAILBOX=http://...

# machine B (same mailbox)
./target/release/mymesh init --label laptop
./target/release/mymesh link <code> --mailbox-dir /shared/mymesh-mb

# both machines
./target/release/mymesh serve --foreground

# laptop → desktop
./target/release/mymesh shell desktop
./target/release/mymesh cp ./file desktop:~/file
./target/release/mymesh cp desktop:~/file ./file
```

### Mailbox options

| Backend | How |
|---------|-----|
| **Filesystem** (same host / NFS) | `--mailbox-dir PATH` or `MYMESH_MAILBOX_DIR` |
| **HTTP** (WAN-friendly) | `mymesh mailbox --bind 0.0.0.0:9876` then `MYMESH_MAILBOX=http://host:9876` |

## CLI

```text
mymesh init [--label NAME]
mymesh status
mymesh link [--mailbox-dir DIR | --mailbox URL]
mymesh link <code>
mymesh devices
mymesh unlink <id|label>
mymesh serve --foreground
mymesh shell <device>
mymesh cp <src> <dst>          # device:path syntax
mymesh mailbox --bind ADDR     # HTTP pairing mailbox
mymesh demo pair|session
mymesh install-notes
```

## Security model

1. SPAKE2 short-code pairing → strong shared secret  
2. Long-term Ed25519 identity = iroh endpoint id  
3. Sessions only from devices in the local allowlist  
4. File ops confined to `sandbox_root` (default `$HOME`)  
5. Wire: QUIC/TLS via iroh  

## License

Apache-2.0 OR MIT
