# MyMesh usage guide (v0.1.0-alpha.3)

This is the practical reference for day-to-day use. For design limits of the magic plane see [ALPHA-3.md](ALPHA-3.md). For linking security see [JOIN.md](JOIN.md) and [SECURITY.md](SECURITY.md). Next-phase contracts: [PAIR-V2.md](PAIR-V2.md), [MASTER-KEY.md](MASTER-KEY.md), [GRANTS.md](GRANTS.md), [GUEST.md](GUEST.md), [CARRIER-NEXT.md](CARRIER-NEXT.md), [CARRIER-ADMIN-NEXT.md](CARRIER-ADMIN-NEXT.md) (Wave F: enrollment, domains, gateway). Wave A pair demo (dual-scan + confirm): [DEMO-PAIR.md](DEMO-PAIR.md). Dual-authority recovery (lost phone/MMK, guest, rotate, sealed backup): [RECOVERY.md](RECOVERY.md).

---

## Concepts

| Term | Meaning |
|------|---------|
| **Identity** | Ed25519 key; **DeviceId** = iroh EndpointId (hex or 24 BIP39 words) |
| **Agent / serve** | Long-lived process: accepts sessions, mesh sync, magic plane, **owns the only iroh endpoint** |
| **Dial proxy** | Unix socket (`$XDG_RUNTIME_DIR/mymesh.sock`) so CLI/TUI dial *through* the agent |
| **Trust** | Device record `Trusted` / `Pending` / `Revoked` |
| **Arm** | Host temporarily accepts new join requests |
| **Mesh** | Shared roster via signed membership gossip |
| **Magic plane** | Local DNS + SOCKS5 + `127.64/16` mesh IPs + TCP tunnels |
| **Label / alias** | Human names for SSH/DNS (`desktop.mym`) |

**Rule:** keep **one** agent per identity. CLI commands use the dial proxy when the agent is up.

---

## Lifecycle

### First-time setup

```bash
mymesh init --label myhost          # identity + config
mymesh install                      # binary → ~/.local/bin, user unit, completions
systemctl --user enable --now mymesh
mymesh status
mymesh service status               # systemctl wrapper
```

### Daily

```bash
systemctl --user status mymesh      # should be active
mymesh                              # TUI
# or CLI:
mymesh devices
mymesh ping <peer>
```

### Upgrade binary

```bash
git pull && cargo build --release -p mymesh-cli
mymesh install                      # re-copies binary + unit
systemctl --user restart mymesh
```

### Uninstall / reset

```bash
mymesh uninstall                    # unit + optional binary
mymesh uninstall --purge            # also wipe state (destructive)
mymesh reset --links                # clear devices (keep identity)
mymesh reset --identity             # new identity (breaks all links)
```

`reset` is **CLI-only** (not exposed as a casual TUI action).

---

## Linking devices

### Default: id join (recommended)

**Host**

```bash
mymesh connect-request allow        # or: mymesh arm allow [--secs 600]
mymesh id                           # hex
mymesh id --words                   # 24 words
mymesh id --uri                     # join URI (QR-friendly)
mymesh id --qr                      # terminal QR of URI
```

**Joiner**

```bash
mymesh link '<hex-or-24-words-or-uri>'
```

**Host**

```bash
mymesh requests list
mymesh requests accept <id-prefix>
# or deny
mymesh connect-request status
mymesh connect-request deny         # disarm early
```

Arm auto-disarms after accept / timeout.

### Pair v2 dual-scan + confirm (Wave A product path)

Internet-first decide without requiring phone HTTP to the host. Full demo checklist: **[DEMO-PAIR.md](DEMO-PAIR.md)**. Contract: [PAIR-V2.md](PAIR-V2.md).

```bash
# Machine A (resident) — mymesh serve must be running
mymesh pair dual                    # QR_A v2 (nonce; ep=confirm if no --host)
# optional LAN HTTP decide (needs mymesh carrier on :17878 — dual --host only sets the QR hint):
# mymesh carrier &
# mymesh pair dual --host http://<lan-ip>:17878

# Machine B (joiner)
mymesh pair dual --join --resident <did-or-words-from-A>   # QR_B + iroh dial

# Phone: scan QR_A then QR_B → L2 Accept/Deny
#   host reachable (carrier up) → POST /pair/v2/decide
#   else → confirm codes on phone; on A:
mymesh pair confirm <CODE>          # Crockford 4-4; hyphens optional
mymesh pair status                  # optional
```

**Honesty:** Carrier `mock-pair-host` is **lab-only** (not in this repo) — not a production pair path. See [DEMO-PAIR.md](DEMO-PAIR.md).

### Connect-by-carrier (phone as scanner — default pair/v2 QR)

Phone must reach the **carrier pair API** on one machine (same LAN, or open carrier port carefully). Default bootstrap QR is **pair/v2** with LAN `host` + `ep=direct` (D5 / KD23). Prefer dual-scan + confirm above when phone cannot reach host HTTP.

```bash
# Machine A
mymesh carrier                      # default: pair/v2 QR + /pair/v2 (page on :17878)
# mymesh carrier --pair-v1          # escape: alpha.1 pair/v1 LAN QR
# scan QR with phone

# Machine B
mymesh id --uri                     # show URI/QR
# paste/scan into phone page  (or: mymesh link <host-id>)

# A completes join over iroh (not through the phone as a node)
```

If the phone cannot load the page / API, check **host firewall** (see below). Carrier binds `0.0.0.0` so LAN clients can connect.

### Optional: SPAKE + local mailbox

For labs / shared folder only — **not** the default WAN path:

```bash
mymesh link --local                 # host
mymesh link --code '…' --local      # guest
```

### Unlink / kick

```bash
mymesh unlink <device>              # local revoke only
mymesh kick <device>                # mesh-wide; double typed confirmation
# TUI Peers: kick / force kick when peer offline → pending delivery
```

---

## Identity & naming

```bash
mymesh id
mymesh id --words
mymesh id --uri
mymesh id --qr

mymesh label desktop homedesktop
mymesh alias desktop desk
mymesh alias desktop --remove desk
mymesh group desktop home
mymesh hosts
mymesh hosts --group home
mymesh resolve desk
mymesh resolve desk.mym
```

Mesh IPs are derived as **127.64.x.y** (loopback range, no root). They are **local addresses** that the magic plane uses for port forwards — not routable on the LAN.

---

## Shell & files

```bash
mymesh shell desktop
mymesh shell desktop -- bash -l

mymesh cp ./local.txt desktop:~/remote.txt
mymesh cp desktop:~/remote.txt ./local.txt
```

**TUI:** Files tab (dual pane, multi-select, node pickers); Term tab (peer picker, PTY).  
**Sandbox:** default file root is your home (config). Paths outside are rejected by the agent.

---

## Connectivity checks

```bash
mymesh ping desktop                 # mesh RTT (not ICMP)
mymesh bw desktop                   # bandwidth probe
mymesh probe-all                    # all trusted peers
mymesh mesh                         # roster / mesh id
mymesh mesh sync                    # push/pull membership now
```

If **ping fails**, fix mesh/agent before SSH or SOCKS.

---

## SSH over the mesh

MyMesh tunnels OpenSSH to the peer’s **localhost:22**. It does not replace `sshd`.

### Setup (client)

```bash
mymesh ping desktop                 # must work
mymesh ssh-config                   # preview
mymesh ssh-config >> ~/.ssh/config  # or Include a drop-in
```

Ensure `ProxyCommand` uses the **installed** binary path (absolute path preferred).

### Remote

```bash
systemctl status ssh                # or sshd
ss -lntp | grep ':22'
```

### Use

```bash
ssh desktop.mym
ssh user@desktop.mym
ssh -v desktop.mym                  # debug ProxyCommand

# manual smoke (stderr progress; then wait — normal without OpenSSH):
mymesh proxy-ssh desktop.mym
# expect: dialing… / dial ok
```

### Troubleshooting SSH

| Symptom | Check |
|---------|--------|
| Hang, no dial ok | Both agents on **alpha.3+**, restarted after upgrade |
| `could not dial 127.0.0.1:22` | Remote sshd |
| `resolve` / not trusted | `mymesh hosts` / re-link |
| dial proxy errors | `ls $XDG_RUNTIME_DIR/mymesh.sock`, `systemctl --user status mymesh` |
| Works in shell, fails under `ssh` | OpenSSH env missing runtime dir — upgrade (alpha.3 probes `/run/user/*/mymesh.sock`) |

---

## Magic plane: DNS, SOCKS, TCP

Started automatically by **`mymesh serve`** when `[magic] enabled = true` (default).

### Config (`~/.config/mymesh/config.toml`)

```toml
[magic]
enabled = true
domain = "mym"
dns_bind = "127.0.0.1:5353"
socks_bind = "127.0.0.1:18080"
auto_ports = [22, 80, 443, 3000, 7878, 8000, 8080, 8443, 9090]
reconnect_probe_secs = 30
```

```bash
mymesh magic                        # help text
```

### DNS (userspace only)

- Answers `label.mym` / aliases → mesh IP  
- **Does not** configure systemd-resolved / NetworkManager by itself  

```bash
dig @127.0.0.1 -p 5353 desktop.mym +short
# system ping desktop.mym → often "Name or service not known" until you wire OS DNS
```

### SOCKS5 (browsers & HTTP tools)

Preferred way to open **web UIs** on peers:

```bash
export ALL_PROXY=socks5h://127.0.0.1:18080
curl -v http://laptop.mym:7878/
```

Browser: SOCKS5 host `127.0.0.1`, port `18080`, **enable proxy DNS** (hostname resolution through SOCKS).

### Auto port forwards

For each trusted peer mesh IP, the agent tries to bind configured ports and tunnel to `peer:port`.  
Docker/k8s services need to listen on the peer host (or be published to the host).

### Manual expose

```bash
mymesh expose laptop 7878           # listen 127.0.0.1:7878 → laptop:7878
mymesh expose laptop 7878 --local-port 17878
```

### Honest limits

- Not a full VPN; mesh IPs exist only on the local machine’s loopback map  
- ICMP `ping host.mym` is **not** a supported mesh diagnostic (use `mymesh ping`)  
- UDP not tunneled  
- Auto-ports are a fixed list (edit config)

---

## Firewall helper (explicit only)

MyMesh **never** opens firewall ports by default. Carrier HTTP (`TCP 17878`) often needs a hole on the host running `mymesh carrier`.

```bash
mymesh firewall explain             # ports & rationale
mymesh firewall status
mymesh firewall ufw allow|deny|status
mymesh firewall firewalld allow|deny|status
```

If not root, errors include the exact:

```bash
sudo /path/to/mymesh firewall ufw allow
```

TUI may try `pkexec` for elevation when available.

**Note:** iroh mesh traffic usually does **not** need UFW opens (outbound + relays). Localhost sshd is not blocked by UFW.

---

## Mesh membership & kicks

```bash
mymesh mesh
mymesh mesh sync
mymesh kick <device>                # interactive double confirm
```

- Membership is **gossiped** (push on change + ~60s validate)  
- Kick can be **pending** if the target is offline; delivered when any member sees them  
- Force kick available in TUI for stuck cases  

---

## TUI map

```bash
mymesh                              # default
mymesh tui
```

| Area | Actions (representative) |
|------|---------------------------|
| **Home** | Status, arm, carrier, link join, copy id/uri/qr, install/service refresh |
| **Peers** | Select peer, ping/bw/metrics, kick, labels, navigate tools |
| **Files** | Dual pane, multi-select, any→any node, auto refresh |
| **Term** | Peer select, interactive PTY (Ctrl+D detaches cleanly) |
| **Status** | Agent/unit, magic, firewall explain, ssh-config preview |

CLI-only (by design for alpha.3): SPAKE mailbox paths, full `reset`, some firewall edge cases without elevation.

---

## Service & status

```bash
mymesh status
mymesh service status|start|stop|restart|enable|disable
systemctl --user status mymesh.service
journalctl --user -u mymesh -f
```

Agent logs should show roughly once at start:

- `iroh endpoint bound`
- `local dial proxy listening`
- `magic DNS ready` / `magic SOCKS5 ready` (if enabled)

**Not** a new `iroh endpoint bound` on every ping (that was the multi-bind bug; fixed in alpha.3).

---

## Completions

```bash
mymesh completions bash
mymesh completions zsh
mymesh completions fish
# install also drops completions when possible
```

---

## Environment & paths

| Variable / path | Role |
|-----------------|------|
| `MYMESH_HOME` | Override state root |
| `MYMESH_CONTROL_SOCK` | Override dial proxy path |
| `~/.config/mymesh/config.toml` | Config |
| `~/.local/share/mymesh/` | devices, mesh, metrics, … |
| `$XDG_RUNTIME_DIR/mymesh.sock` | Dial proxy (default) |

---

## Demo / dev helpers

```bash
mymesh demo pair                    # local SPAKE demo
mymesh mailbox                      # HTTP SPAKE mailbox server
```

Wave A pair product demo (dual-scan + confirm, two-agent harness, lab honesty): **[DEMO-PAIR.md](DEMO-PAIR.md)**.

---

## Quick diagnosis flowchart

```text
ping fails?
  → agent active both sides? same link/trust? journalctl?
ping ok, shell/cp fail?
  → capabilities Trusted+Terminal/Files? sandbox paths?
ping ok, ssh hangs?
  → alpha.3+ both sides? sshd on remote? proxy-ssh stderr?
browser *.mym fails?
  → SOCKS5h to socks_bind? service listening on peer?
carrier phone timeout?
  → firewall explain + ufw allow carrier port?
```

---

## See also

- [ALPHA-3.md](ALPHA-3.md) — magic plane  
- [JOIN.md](JOIN.md) — pairing details  
- [PAIR-V2.md](PAIR-V2.md) · [DEMO-PAIR.md](DEMO-PAIR.md) · [MASTER-KEY.md](MASTER-KEY.md) · [GRANTS.md](GRANTS.md) · [GUEST.md](GUEST.md)  
- [RECOVERY.md](RECOVERY.md) — dual-authority recovery runbooks  
- [SECURITY.md](SECURITY.md) — operator security model  
- [THREATS.md](THREATS.md) — threat catalog + S9 control checklist C1–C7  
- [CARRIER-NEXT.md](CARRIER-NEXT.md) — S0–S9 design  

- [ROADMAP.md](ROADMAP.md) — next releases  
