# MyMesh v0.1.0-alpha.3 — Magic plane

Theme: **use your mesh like a LAN** (without a full VPN).

This release ships non-GUI “magic” features: names, SSH, TCP tunnels, SOCKS, DNS, carrier join, labels. Operational guide: [USAGE.md](USAGE.md).

---

## Feature summary

### 1. Labels / aliases / groups

```bash
mymesh label <device> homedesktop
mymesh alias <device> desk
mymesh group <device> home
mymesh hosts
mymesh hosts --group home
mymesh resolve desk
```

Names feed SSH config, DNS answers, and SOCKS host resolution.

### 2. Always-up agent + single endpoint

- `mymesh install` → user systemd unit with `Restart=always`
- **One iroh endpoint per identity**, owned by `serve`
- **Dial proxy** on `$XDG_RUNTIME_DIR/mymesh.sock` so CLI/TUI never re-bind the same key
- Reconnect probes use the **shared** transport (no second bind)

### 3. SSH `*.mym`

```bash
mymesh ssh-config >> ~/.ssh/config
ssh user@homedesktop.mym
# ProxyCommand: mymesh proxy-ssh %h  → TCP tunnel → peer 127.0.0.1:22
```

Requires remote **sshd**. Mesh path must already work (`mymesh ping`).

### 4. TCP mesh-IP + port pipe

- Each device: stable **127.64.x.y** (loopback-mapped, no root)
- `serve` auto-binds configured ports on each peer IP → tunnel to peer `127.0.0.1:port`
- Default auto ports: 22, 80, 443, 3000, 7878, 8000, 8080, 8443, 9090
- Manual: `mymesh expose laptop 7878`

Docker / k8s: publish the service on the **host** of a mesh node; clients use mesh IP/port or SOCKS.

### 5. DNS for `*.mym` (userspace)

- UDP DNS on `127.0.0.1:5353` (`magic.dns_bind`)
- Resolves `label.mym` / aliases → mesh IPs
- **Not** installed into systemd-resolved by default
- Test: `dig @127.0.0.1 -p 5353 laptop.mym +short`
- System `ping laptop.mym` fails until you wire OS DNS (ICMP also not a mesh feature)

### 6. Browser / HTTP without system DNS

```bash
export ALL_PROXY=socks5h://127.0.0.1:18080
curl -v http://laptop.mym:7878/
```

SOCKS5 from `serve` (`magic.socks_bind`). Prefer **`socks5h`** / “proxy DNS” so names resolve inside MyMesh.

### 7. Connect-by-carrier

Phone is a **scanner only** (no mesh node, no Android app).

```bash
# A (phone on a network that can reach A's :17878)
mymesh carrier

# B
mymesh id --uri   # scan/paste into phone page

# A dials B over iroh and completes join
```

Symmetric: either side can host the page. Firewall may block LAN access to `:17878` — use `mymesh firewall explain`.

---

## Config

```toml
[magic]
enabled = true
domain = "mym"
dns_bind = "127.0.0.1:5353"
socks_bind = "127.0.0.1:18080"
auto_ports = [22, 80, 443, 3000, 7878, 8000, 8080, 8443, 9090]
reconnect_probe_secs = 30
```

---

## Architecture notes (alpha.3)

```text
┌─────────────┐   dial proxy    ┌──────────────────┐   iroh/QUIC   ┌─────────────┐
│ CLI / TUI   │ ──────────────► │ mymesh serve     │ ◄──────────► │ peer serve  │
│ proxy-ssh   │  Unix socket    │ endpoint + agent │              │ sshd :22    │
└─────────────┘                 │ magic DNS/SOCKS  │              │ :7878 …     │
                                └──────────────────┘              └─────────────┘
```

**Do not** run two processes that `IrohTransport::bind` the same identity. That caused `connection lost` / timeouts before the dial-proxy fix.

---

## Related fixes in the alpha.3 window

- Bandwidth probe channel filter (ignore control gossip)
- Firewall helper (ufw / firewalld, explicit)
- Ctrl+D safe shell detach in TUI
- Shell/completions coverage
- TCP/SSH full-duplex deadlock fix (`proxy-ssh` hang)
- OpenSSH missing `XDG_RUNTIME_DIR` → control socket discovery

---

## Honest limits

| Limit | Detail |
|-------|--------|
| Not a TUN VPN | No system-wide capture; mesh IPs are local loopback maps |
| Auto-ports finite | Extend `magic.auto_ports` |
| System DNS | Manual stub resolver / future install helper |
| ICMP | Use `mymesh ping`, not `ping(8)` |
| UDP | Not tunneled |
| Desktop GUI control | Deferred |
| Hyprland fullscreen TUI chrome | Known imperfect; parked |
| Carrier port | Often needs explicit host firewall allow |

---

## Validation checklist (maintainer)

- [ ] Link two machines (id join) both ways  
- [ ] `mymesh ping` / `bw` / TUI metrics  
- [ ] `shell` + `cp` both directions  
- [ ] `ssh host.mym` both directions  
- [ ] SOCKS `curl` to a peer HTTP port  
- [ ] Carrier join once on LAN  
- [ ] Kick + pending kick when offline  
- [ ] Restart agents; dial proxy still works  
