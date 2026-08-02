# Release notes — v0.1.0-alpha.3

**Date:** 2026-08-02  
**Codename theme:** Magic plane  

## Highlights

1. **SSH into mesh hosts** — `mymesh ssh-config` + `ssh host.mym` via TCP tunnel to peer sshd.  
2. **Browse services** — SOCKS5 on the agent (`socks5h://127.0.0.1:18080`) for `http://host.mym:port`.  
3. **Names** — labels, aliases, groups, `hosts` / `resolve`.  
4. **Stable agent networking** — single iroh endpoint + local dial proxy (fixes flaky sessions).  
5. **Carrier join** — phone scans two QRs; never joins the mesh.  

## Install

```bash
git clone https://github.com/jtwolfe/MyMesh.git
cd MyMesh && git checkout v0.1.0-alpha.3
cargo build --release -p mymesh-cli
./target/release/mymesh install
systemctl --user enable --now mymesh
```

Attach a release binary if you publish assets; otherwise build from the tag.

## Upgrade from alpha.2

```bash
git fetch --tags
git checkout v0.1.0-alpha.3
cargo build --release -p mymesh-cli
mymesh install
systemctl --user restart mymesh
# both machines — required for SSH/TCP duplex + dial proxy
```

Re-run `mymesh ssh-config` if your ProxyCommand path changed.

## Docs

- [USAGE.md](USAGE.md) — full usage  
- [ALPHA-3.md](ALPHA-3.md) — magic plane  
- [CHANGELOG.md](../CHANGELOG.md)  

## Known issues

- OS does not resolve `*.mym` unless you configure DNS  
- TUI chrome under some Hyprland fullscreen paths  
- Alpha quality — expect further CLI changes  
