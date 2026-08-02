## MyMesh v0.1.0-alpha.1

First tagged **alpha**. Early adopters only. CLI and on-disk formats may change.

### Highlights

- **Link devices** with request/accept (host arms → joiner links by id → host accepts → auto-disarm)
- **24-word** BIP39 device ids (or 64-char hex)
- **Remote shell** and **file copy** over iroh (P2P + relays)
- Works across networks when both peers have outbound internet and `serve` is running

### Install / run

```bash
git clone https://github.com/jtwolfe/MyMesh.git
cd MyMesh && git checkout v0.1.0-alpha.1
cargo build --release -p mymesh-cli
./target/release/mymesh init --label mybox
./target/release/mymesh serve --foreground
```

See the [README](https://github.com/jtwolfe/MyMesh/blob/v0.1.0-alpha.1/README.md) for the full link flow.

### Not in this release

- systemd / `mymesh install`
- TUI
- Desktop remote control
- distro packages / one-line installer
- `*.mym` SSH hostnames

### Next

**v0.1.0-alpha.2** — install/uninstall/reset, user systemd unit, TUI default, peer metrics.

Full notes: [CHANGELOG.md](https://github.com/jtwolfe/MyMesh/blob/v0.1.0-alpha.1/CHANGELOG.md)
