# MyMesh v0.1.0-alpha.3 — Magic plane

Theme: **use your mesh like a LAN** (non-GUI).

## Features

### 1. Labels / aliases / groups
```bash
mymesh label <device> homedesktop
mymesh alias <device> desk
mymesh group <device> home
mymesh hosts
mymesh hosts --group home
mymesh resolve desk
```

### 2. Always-up agent + reconnect
- `mymesh install` uses `Restart=always`
- `mymesh serve` probes trusted peers on an interval (`magic.reconnect_probe_secs`, default 30s)
- Updates `last_seen` when a probe succeeds

### 3. SSH `*.mym`
```bash
mymesh ssh-config >> ~/.ssh/config
ssh user@homedesktop.mym
# uses: mymesh proxy-ssh %h  → TCP tunnel to peer:22
```

### 4. TCP mesh-IP + port pipe
- Each device gets a stable **127.64.x.y** address (loopback, no root)
- `mymesh serve` auto-binds configured ports on each peer IP and tunnels to peer `127.0.0.1:port`
- Default auto ports: 22, 80, 443, 3000, 7878, 8000, 8080, 8443, 9090
- Manual: `mymesh expose laptop 7878` → listen `127.0.0.1:7878` → peer:7878

Docker / k8s ingress: if it listens on the host (or hostPort/NodePort), mesh IP + port reaches it.

### 5. DNS for `*.mym`
- Userspace DNS on `127.0.0.1:5353` (config: `magic.dns_bind`)
- Resolves `label.mym` / aliases to mesh IPs
- Point a stub resolver at it, **or** use SOCKS (below)

### 6. Browser without special DNS
```bash
export ALL_PROXY=socks5://127.0.0.1:18080
# then: http://laptop.mym:7878
```
SOCKS5 is started by `mymesh serve` (`magic.socks_bind`).

### 7. Connect by carrier (phone = scanner only)
```bash
# machine A (phone on same LAN as A)
mymesh carrier
# scan QR → phone opens page

# machine B
mymesh id --uri
# paste/scan that URI into the phone page

# A dials B over iroh and completes join
```
No Android app. Phone never joins the mesh.

## Config (`~/.config/mymesh/config.toml`)

```toml
[magic]
enabled = true
domain = "mym"
dns_bind = "127.0.0.1:5353"
socks_bind = "127.0.0.1:18080"
auto_ports = [22, 80, 443, 3000, 7878, 8000, 8080, 8443, 9090]
reconnect_probe_secs = 30
```

## Honest limits
- Not a full TUN VPN — mesh IPs live in 127.64/16 on the local host only
- Auto-ports only cover the configured list (extend in config)
- System-wide DNS needs you to wire `dns_bind` into your resolver
- Hyprland fullscreen TUI chrome issues remain parked
- UDP not tunneled yet
