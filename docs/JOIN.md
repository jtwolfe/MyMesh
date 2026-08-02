# Linking devices

**Release:** v0.1.0-alpha.1

## Default model (recommended)

MyMesh does **not** require both sides to paste ids.

1. **Host** runs the agent (`mymesh serve`) and temporarily allows joins:
   ```bash
   mymesh connect-request allow          # optional: --secs 600
   mymesh id                             # hex + 24 words + URI
   ```
2. **Joiner** requests a link (host id = hex or 24 words):
   ```bash
   mymesh link '<host-id>'
   ```
3. **Host** reviews and accepts:
   ```bash
   mymesh requests list
   mymesh requests accept <short-id|label|hex>
   ```
4. After accept, **arming turns off automatically**. Further unknown joiners are rejected until you arm again.
5. Both machines store a **Trusted** device record. Later sessions use **dial-by-device-id** over iroh (no re-pair when you change Wi‑Fi), as long as both agents are running and can reach the internet/relays.

### Commands

| Command | Role |
|---------|------|
| `connect-request allow` | Arm host for join requests |
| `connect-request deny` | Disarm immediately |
| `connect-request status` | Armed or not |
| `link <id>` | Joiner: send request and wait |
| `link` (no args) | Print how-to + your id |
| `requests list\|accept\|deny` | Host operator actions |

### While disarmed

Untrusted peers that connect for a join are **rejected**. Trusted peers can still open shell/files sessions.

### Moving networks

After a successful link, the allowlist is identity-based. A laptop that leaves home Wi‑Fi can still reach a desktop (and vice versa) via iroh hole punch / relay. You do **not** re-run `link` for that. Active sessions may drop; start a new `shell`/`cp`.

---

## Device identifiers

| Form | Description |
|------|-------------|
| **Hex** | Canonical 32-byte public key, 64 hex characters |
| **Words** | BIP39 English, **24 words**, same 32 bytes + checksum |
| **URI** | `mymesh:v1:join:<hex>` — for QR generators / future scanners |

```bash
mymesh id
mymesh id --words
mymesh id --uri
```

Wire protocol and storage always use the raw key; words are a display encoding only.

---

## Advanced: SPAKE / local mailbox

For labs, shared directories, or experiments **without** the request/accept path:

```bash
# host
mymesh link --local
# prints a short code like 254-sail-falcon

# guest
mymesh link --code 254-sail-falcon --local
```

Also: `--mailbox-dir /path`, `MYMESH_MAILBOX=http://host:port` with `mymesh mailbox`.

**Caveat:** a filesystem mailbox is only shared if both processes see the **same** directory (not two machines’ separate `/tmp`). Prefer the default id-based join for real multi-machine use.

---

## Failure modes (common)

| Symptom | Likely cause |
|---------|----------------|
| Joiner hangs on “waiting for approval” | Host did not `requests accept`, or `serve` not running |
| Joiner fails immediately | Host not armed, or wrong id |
| Shell/cp “not trusted” | Link never completed on both sides |
| Connect works at home, fails elsewhere | No outbound internet / relay blocked on one side |
| SPAKE with `--mailbox-dir /tmp/...` hangs across PCs | Different filesystems — not a shared mailbox |

---

## See also

- [SECURITY.md](SECURITY.md) — trust and arming model  
- [ROADMAP.md](ROADMAP.md) — alpha.2 install/TUI  

## Mesh membership (gossip)

After a join is accepted, the host sends a **membership snapshot** of all trusted
devices. The joiner merges them into its allowlist, so peers that only linked to
the hub also learn about each other.

- `mymesh mesh status` — mesh id + roster  
- `mymesh mesh sync` — pull/push membership with each trusted peer (agents must run)  
- Session gossip: agents also push snapshots on connect  

## Kick from mesh

```bash
mymesh kick <label-or-id>
# Type: KICK FROM MESH
# Type: I AM SURE
```

Effects:

1. Direct `KickNotice` to the target: *you were kicked from the mesh by X host*
2. `KickAnnounce` gossip to other members (they drop the target)
3. Local remove of the target
4. Kicked node clears its mesh roster and writes `kick-notice.txt`
