# Linking devices

**Release:** v0.1.0-alpha.3 (behavior) · **S0 contracts:** pair v2 / grants / guest / master key (docs freeze)

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

# guest (SPAKE peer — not mesh_role=guest; see GUEST.md for share-one-device)
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

## Mesh membership (gossip)

After a **member** join is accepted, the host sends a **membership snapshot** of all trusted
**member** devices. The joiner merges them into its allowlist, so peers that only linked to
the hub also learn about each other.

- `mymesh mesh status` — mesh id + roster  
- `mymesh mesh sync` — pull/push membership with each trusted peer (agents must run)  
- Session gossip: agents also push snapshots on connect  

**Guest exception (S0 contract):** guests do **not** receive mesh-wide `MembershipSnapshot`. See [GUEST.md](GUEST.md).

---

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

Kick is the primary tool for **members**. For **guests**, use grant revoke ([GRANTS.md](GRANTS.md), [GUEST.md](GUEST.md)).

## Pending kicks

If the kickee is offline, every mesh member stores a **pending kick**. When the
kickee next appears to any online member, that member delivers `KickNotice`.
The kickee then sends **KickLeaveAck** to all known peers so the mesh converges.

- `mymesh kick <id>` — double confirm; queues pending if offline  
- `mymesh kick <id> --force` — force remove immediately; still queues notice  
- Agent: mesh push on dirty roster + **validate every 60s**  
- TUI Peers: `[K]` kick, `[F]` force, `[g]` sync, pending list

---

## Connect-by-carrier (alpha.3 / pair v1)

Phone acts as a **scanner / approver only** (not a mesh node). See [USAGE.md](USAGE.md) and [ALPHA-3.md](ALPHA-3.md).

```bash
mymesh carrier          # machine A — exposes /pair/v1 (LAN host in QR)
mymesh id --uri         # machine B → phone page
```

### Pair v1 (shipped)

| Field | Behavior |
|-------|----------|
| QR | `carrier://pair?v=1&host=<LAN>&token&fp&mesh` |
| `host` | **Required** |
| Endpoints | `/pair/v1/status`, `pending`, `decide` |
| Decide | Phone HTTP to host; L2 step-up on Carrier |
| Outcome | JoinStore decision → member Accept + **full** membership snapshot |

### Pair v2 (S0 contract — implement S1–S2)

Internet-first product path: **optional** `host`, required session **nonce**, dual-scan + **confirm-on-machine** when phone cannot reach pair HTTP. Full freeze: **[PAIR-V2.md](PAIR-V2.md)**.

| | pair/v1 (alpha) | pair/v2 (next) |
|--|-----------------|----------------|
| `host` | Required | Optional |
| `nonce` | — | **Required** (16B base64url) |
| `sid` / `did` / `ep` | — | Required |
| Zero-HTTP decide | — | Confirm codes (Crockford **4-4**, e.g. `ABCD-EFGH`) |
| Unbound confirm | — | **`not_bound` fail closed** (no hang) |
| Endpoints | `/pair/v1/*` | `/pair/v2/*` + v1 compat |

```text
# v2 QR sketch
carrier://pair?v=2&sid=<ulid>&did=<64hex>&token=<b64url>&nonce=<b64url-16B>&fp=<fp>
                 &ep=direct|confirm|relay&host=<optional>&mesh=<optional>
```

CLI (implemented): `mymesh pair dual`, `pair dual --join`, `pair confirm <code>`, `pair status`, `pair retry`. E2E demo steps and lab honesty: **[DEMO-PAIR.md](DEMO-PAIR.md)**.

**Migration policy:** v1 accepted through compat window; `pair dual` emits v2 after A3; `mymesh carrier` stays v1 until D5 then v2 default with `--pair-v1`. Details in [PAIR-V2.md](PAIR-V2.md) and [CARRIER-NEXT.md](CARRIER-NEXT.md) Appendix A.

---

## Ceremonies catalog (S0)

| Ceremony | Phone? | Success |
|----------|--------|---------|
| **CLI link** | No | Both Trusted **members**; full roster snapshot |
| **Single-host pair (v1/v2 direct)** | Yes if Carrier decide; or CLI accept | Member join + full snapshot |
| **Dual-scan + confirm** | Scan UX needs phone; confirm can be operator-only | Bound session → decided → iroh complete |
| **Guest share** | Optional | Bilateral trust + Grant; **no full roster** — [GUEST.md](GUEST.md) |
| **Master key bootstrap** | No | [MASTER-KEY.md](MASTER-KEY.md) |

---

## Admin capability (migration note)

- Default member grant remains **without** `Admin` (terminal/files/desktop/tcp).
- Host-local CLI always retains node admin (filesystem trust).
- After mesh master key init (S3), remote Admin is explicit: MMK proof, person owner, or `devices grant-admin`. See [MASTER-KEY.md](MASTER-KEY.md) and [SECURITY.md](SECURITY.md).

---

## See also

- [PAIR-V2.md](PAIR-V2.md) — pair v2 wire, nonce, confirm 4-4 Crockford, `not_bound`  
- [MASTER-KEY.md](MASTER-KEY.md) — mesh master key / policy root  
- [GRANTS.md](GRANTS.md) — grant schema  
- [GUEST.md](GUEST.md) — guest membership; no full roster  
- [SECURITY.md](SECURITY.md) — trust and arming model  
- [CARRIER-NEXT.md](CARRIER-NEXT.md) — full S0–S9 design  
- [ROADMAP.md](ROADMAP.md) — release plan  
- [USAGE.md](USAGE.md) / [ALPHA-3.md](ALPHA-3.md) — carrier and magic plane  
