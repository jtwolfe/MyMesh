# Release notes — v0.1.0-alpha.3

**Date:** 2026-08-02

## Highlights

1. **SSH into mesh hosts** — `mymesh ssh-config` + `ssh host.mym` via TCP tunnel to peer sshd.
2. **Browse services** — SOCKS5 on the agent (`socks5h://127.0.0.1:18080`) for `http://host.mym:port`.
3. **Names** — labels, aliases, groups, `hosts` / `resolve`.
4. **Stable agent networking** — single iroh endpoint + local dial proxy (fixes flaky sessions).
5. **Carrier join** — phone scans QR; never joins the mesh.

## Install from source

```bash
git clone https://github.com/jtwolfe/MyMesh.git
cd MyMesh && git checkout v0.1.0-alpha.3
cargo build --release -p mymesh-cli
./target/release/mymesh install
systemctl --user enable --now mymesh
```

## Install from release binary

```bash
# after downloading mymesh-linux-x86_64 (or your arch) from the GitHub release
chmod +x mymesh-linux-x86_64
./mymesh-linux-x86_64 install
systemctl --user enable --now mymesh
```

## Upgrade from alpha.2

```bash
git fetch --tags
git checkout v0.1.0-alpha.3
cargo build --release -p mymesh-cli
mymesh install
systemctl --user restart mymesh
# both machines — required for SSH/TCP + dial proxy
```

Re-run `mymesh ssh-config` if your ProxyCommand path changed.

## Docs

- [USAGE.md](https://github.com/jtwolfe/MyMesh/blob/v0.1.0-alpha.3/docs/USAGE.md)
- [ALPHA-3.md](https://github.com/jtwolfe/MyMesh/blob/v0.1.0-alpha.3/docs/ALPHA-3.md)
- [CHANGELOG.md](https://github.com/jtwolfe/MyMesh/blob/v0.1.0-alpha.3/CHANGELOG.md)

## Known issues

- OS does not resolve `*.mym` unless you configure DNS
- TUI chrome under some Hyprland fullscreen paths
- Alpha quality — expect further CLI changes
