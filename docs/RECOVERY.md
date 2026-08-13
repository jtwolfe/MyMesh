# Recovery runbooks (dual authority)

| Field | Value |
|-------|--------|
| **Audience** | Operators recovering from loss / compromise on a personal mesh |
| **Status** | Ops runbooks for dual authority (MMK + person owner); not a formal audit |
| **Contract** | [MASTER-KEY.md](MASTER-KEY.md) (recovery matrix, crypto, CLI shape) |
| **Threats** | [THREATS.md](THREATS.md) · operator model [SECURITY.md](SECURITY.md) |
| **Owner / claim** | [MASTER-KEY.md](MASTER-KEY.md) §Owner claim · CLI `mymesh owner *` (Carrier mirrors `OWNERSHIP.md`) |
| **Pair demo** | [DEMO-PAIR.md](DEMO-PAIR.md) — re-pair machines after nuclear recovery |
| **Source** | [CARRIER-NEXT.md](CARRIER-NEXT.md) §dual authority, §S9 runbooks |

---

## Dual authority in one page

| Authority | Role | Survives loss of… |
|-----------|------|-------------------|
| **MMK / MRK** | **Root of mesh policy** — clear/replace owner, rotate policy identity, MRK admin proof | Phone / person seed (if MMK password or recovery codes remain) |
| **Person owner claim** | Portable person binding in `mesh-owner.json`; day-to-day remote admin | MMK password **only if** recovery codes **or** (planned) owner-proof path still work |
| **Host-local CLI** | Filesystem access to agent `Paths` = admin of **this node** | Remote proofs; **cannot** invent MMK/MRK from disk alone when wrap is locked |
| **Remote Admin cap** | Explicit grant on a Trusted **member** | Not a substitute for MMK destructive ops |

**Invariants (normative — [MASTER-KEY.md](MASTER-KEY.md)):**

1. MMK wins over person-owner and remote Admin for mesh-destructive ops.
2. Compromising a **guest** never yields MMK or person seed.
3. `owner-backup.sealed` without the backup password does not yield the person seed.
4. Sealed person backup is **independent** of MRK (password-AEAD only).

---

## CLI inventory (honest — what this tree implements)

Verify with `mymesh mesh --help`, `mymesh owner --help`, `mymesh grant --help`.

### Mesh master key (`mymesh mesh`)

| Command | Status | Notes |
|---------|--------|-------|
| `mesh init [--password-file] [--force]` | **Implemented** | Password + print recovery codes **once**; `--force` overwrites `mesh-master.json` (destructive) |
| `mesh unlock \| lock \| status` | **Implemented** | Host-local `mmk-runtime.json` cache; **not** OS keyring |
| `mesh rotate-master` | **Implemented** | Re-wraps **same** MRK under a new password (current password required) |
| `mesh recover-master --code <hex>` | **Implemented** | One-time recovery code → **new MRK** + new password; bumps owner `mrk_fingerprint` / `mrk_epoch` without clearing claim (KD28) |
| `mesh recover-master --owner-proof` | **Flag only — not wired** | CLI prints that challenge/sign flow is not yet implemented; use `--code` for now |
| `mesh prove` | **Implemented** | MRK admin proof over challenge (unlocked MMK) |
| `mesh sync` | **Implemented** | Membership gossip |

Password sources (order): `--password-file`, `MYMESH_MMK_PASSWORD`, interactive prompt.

### Person owner (`mymesh owner`)

| Command | Status | Notes |
|---------|--------|-------|
| `owner allow-claim --secs N` | **Implemented** | Requires **unlocked** MMK at mint; writes `claim-window.json` |
| `owner claim --person-id … --person-pubkey … --sig-file …` | **Implemented** | MMK unlock **or** valid claim window; `--replace` needs live unlock |
| `owner show` | **Implemented** | Claim + backup slot presence |
| `owner clear --yes` | **Implemented** | Requires unlocked MMK; also removes `owner-backup.sealed` |
| `owner backup export --out PATH` | **Implemented** | Copy sealed blob off-host |
| `owner backup import --input PATH` | **Implemented** | Install sealed blob into agent Paths |
| `owner backup store --person-id … --seed-hex …` | **Implemented** | Air-gap / test helper: seal 32B seed under password |
| Unseal seed to restore phone Keystore | **Not a MyMesh CLI product path** | Crypto `unseal_owner_backup` exists for tests/store smoke-check; **phone restore UX lives on Carrier** (import sealed file + backup password). This repo stores/exports the blob only |

### Guest / members (related recovery actions)

| Command | Status | Use in recovery |
|---------|--------|-----------------|
| `grant list \| create \| revoke <id>` | **Implemented** | Compromised guest — revoke first |
| `unlink <device>` | **Implemented** | Drop local trust for a peer |
| `kick <device>` | **Implemented** | Mesh-wide member removal (double confirm) |
| `devices grant-admin \| revoke-admin` | **Implemented** | Remote Admin only; not MMK |
| `pair dual` / `pair confirm` | **Implemented** | Re-pair after nuclear re-init — [DEMO-PAIR.md](DEMO-PAIR.md) |
| `reset --links` / `--identity` | **Implemented** | Local nuclear helpers (see nuclear runbook) |
| `enroll list \| add \| revoke <person_id>` | **Implemented** | Stolen phone — revoke `can_drive` on **this** node (**C9**) |

### On-disk artifacts (agent `Paths`, mode 0600 where written)

| File | Content |
|------|---------|
| `mesh-master.json` | Argon2id-wrapped MRK + recovery **hashes** (not codes) |
| `mmk-runtime.json` | Unlocked MRK cache after `mesh unlock` |
| `mesh-owner.json` | Person owner claim (not a device role) |
| `owner-backup.sealed` | Password-AEAD person seed backup |
| `claim-window.json` | Short-lived MMK-authorized claim window |
| `devices.json` / `grants.json` | Trust + guest grants |
| `enrollments.json` | Person enrollments (`can_drive`); mode 0600 |

---

## Recovery matrix (summary)

Same matrix as [MASTER-KEY.md](MASTER-KEY.md); runbooks below expand each row.

| # | Lost | Still have | Recovery path |
|---|------|------------|---------------|
| R1 | Phone | Sealed backup + password | Restore person on new phone; re-auth as owner |
| R2 | Phone + backup password | MMK | MMK clears/replaces owner; new claim |
| R3 | Phone + backup + MMK | — | Nuclear: new mesh / re-pair; abandon old mesh_id |
| R4 | MMK password | Recovery codes **or** (planned) owner proof + phone | `recover-master --code` (**today**); `--owner-proof` planned |
| R5 | MMK + owner phone | Sealed backup on disk + password | Restore phone first (R1), then R4 if MMK still lost |
| R6 | MMK + owner + backup | Trusted member + host-local CLI | Node still runs; **no** remote MMK proof; codes at init recommended; else nuclear |
| — | Guest device compromised | Host / owner / MMK intact | Revoke grant; optional unlink (not kick) |
| — | Enrolled phone stolen / lost | Host + MMK intact | **Runbook ER** — `enroll revoke` on each node; pair confirm is not enroll |
| — | MMK password **leaked** (not lost) | Still know password | `rotate-master` (same MRK) **or** recover + new codes if wrap may be offline-attacked |

---

## Runbook R1 — Lost phone (sealed backup + password available)

**Goal:** Same person identity on a new phone; existing `mesh-owner.json` claim remains valid if person keys match.

### Preconditions

- [ ] You have a copy of `owner-backup.sealed` (from mesh host, export, or offline copy)
- [ ] You know the **backup password** (independent of MMK password)
- [ ] At least one mesh host still has `mesh-owner.json` claiming that person

### Steps (MyMesh host)

```bash
# Confirm claim + backup slot on a host with agent Paths
mymesh owner show
# backup_slot should show stored, or import from offline copy:

mymesh owner backup export --out ~/secure/owner-backup.sealed   # if not already offline
# or restore blob onto this host:
mymesh owner backup import --input ~/secure/owner-backup.sealed
mymesh owner show
```

### Steps (Carrier phone — product restore)

1. Install Carrier on the **new** phone.
2. **Restore person** from sealed backup file + backup password (Carrier `OWNERSHIP` / restore UX — not `mymesh` CLI unseal).
3. Unlock person vault; open mesh topology / owner session against a host (mesh API person_owner auth when available).
4. Verify `mymesh owner show` still lists the same `person_id` / pubkey after phone re-auth.

### What you do **not** need

- MMK password (for restore of person seed)
- Re-`mesh init` or re-pair of Trusted members (claim is person binding, not phone hardware)

### If restore fails (wrong password / corrupt blob)

- Wrong password fails closed (Argon2id + AEAD) — no partial seed.
- Fall through to **R2** if you still have MMK; else **R3** nuclear.

### Residual risk

- Weak backup password remains offline-attackable if the sealed file was stolen ([THREATS.md](THREATS.md) **C3** / **C7**).
- Prefer a **strong** backup password; treat exported sealed files like seed material.

---

## Runbook R2 — Lost phone **and** backup password (MMK still known)

**Goal:** Replace person-owner with a new claim under MMK policy root.

### Preconditions

- [ ] You know the **MMK password** (or can unlock via recovery code first — R4)
- [ ] Host-local access to agent data dir

### Steps

```bash
mymesh mesh unlock
mymesh owner show

# Mesh-destructive: clears mesh-owner.json and removes owner-backup.sealed
mymesh owner clear --yes

# New person (new phone vault) claims ownership
mymesh mesh unlock   # if locked again
mymesh owner allow-claim --secs 300
# Preferred: Carrier claim UX posts person-signed claim while window open
# Or CLI air-gap:
# mymesh owner claim --person-id … --person-pubkey … --sig-file ./claim.sig

mymesh owner show
# Strongly recommended: store a fresh sealed backup
mymesh owner backup store --person-id … --seed-hex …   # test/air-gap
# Production phone: PUT /mesh/v1/owner/backup with person_owner session (when using carrier HTTP)
```

### Notes

- `owner clear` requires **unlocked** MMK (`--yes` alone is not enough).
- Second claim without clear needs `owner claim … --replace` **and** live MMK unlock.
- Old phone person keys are **orphaned** for this mesh; revoke any Carrier sessions on the lost device if the OS allows wipe.

---

## Runbook R3 — Nuclear (lost phone + backup + MMK)

**Goal:** Abandon old policy roots; build a new personal mesh.

### When

- No MMK password, no recovery codes, no sealed backup password, and no path to owner proof.
- Or deliberate full rekey after catastrophic compromise of all roots.

### Effect

- Old `mesh_id` / MRK / owner claim are **untrusted forever**.
- Trusted peers must be **re-linked** (CLI accept or [DEMO-PAIR.md](DEMO-PAIR.md) dual-scan).

### Steps (per host you still control)

```bash
# Stop agent if running
systemctl --user stop mymesh   # if installed as user unit

# Option A — soft: drop links/roster, keep device identity
mymesh reset --links

# Option B — hard: new device identity (new device id / iroh endpoint)
mymesh reset --identity
mymesh init --label <host>

# New MMK (prints recovery codes ONCE — store offline)
mymesh mesh init --force     # if mesh-master.json still present from old mesh
# or first-time:
mymesh mesh init

mymesh mesh unlock
# Optional owner claim on new mesh
mymesh owner allow-claim --secs 300
# … claim + backup store as in R2 …

systemctl --user start mymesh
```

### Re-pair peers

```bash
# Classic CLI path
# Host:  mymesh connect-request allow && mymesh id
# Peer:  mymesh link '<host-id>'
# Host:  mymesh requests accept <prefix>

# Or Wave A dual-scan + confirm — see DEMO-PAIR.md
mymesh pair dual
# joiner: mymesh pair dual --join --resident <id>
# host:   mymesh pair confirm <code>
```

### Honest limits

- Host-local CLI cannot reconstruct MMK from ciphertext without password/codes.
- Peers that still hold old membership data must be unlinked/reset so they do not present stale trust.

---

## Runbook R4 — Lost MMK password (recovery codes available)

**Goal:** New MRK + new MMK password; **keep** person owner claim (KD28).

### Preconditions

- [ ] One unused recovery code from `mesh init` (256-bit hex, printed once)
- [ ] Host-local CLI on a machine with `mesh-master.json`

### Steps

```bash
mymesh mesh status
# master initialized; recovery_codes count > 0

mymesh mesh recover-master --code <recovery-hex>
# prompts for NEW mesh master password (confirm)
# consumes that recovery code; generates new MRK; re-wraps mesh-master.json

mymesh mesh unlock
mymesh mesh status
mymesh owner show
# claim retained; mrk_fingerprint updated; mrk_epoch incremented
```

### After recovery

1. **Record remaining recovery codes** if you still have the original printout; the used code is dead.
2. Unlock on other hosts that share the same `mesh-master.json` only if you deliberately sync policy files — **typical** personal mesh: each policy root is per-agent Paths; recover on the policy host you use for admin.
3. Remote `mrk_proof` sessions minted under the **old** MRK fail; re-unlock / re-auth as needed.
4. Person owner sessions (person Ed25519) remain valid for day-to-day owner UX; fingerprint display may show new epoch.

### If you have no recovery codes

| Still have | Action |
|------------|--------|
| Working owner phone + claim | **Planned:** `mymesh mesh recover-master --owner-proof` (challenge signed by person). **Today: not implemented** — flag exists and errors with guidance to use `--code`. |
| Sealed backup + password only | Restore phone first if needed; still need codes or owner-proof for MMK — backup does **not** unwrap MRK. |
| Nothing | **R3** nuclear or **R6** host-local-only operation without MMK |

---

## Runbook R5 — Lost MMK + lost owner phone (sealed backup remains)

**Goal:** Restore person first, then recover MMK if codes exist.

```text
1. R1 — restore person from owner-backup.sealed + backup password (Carrier)
2. If recovery codes exist → R4 (recover-master --code)
3. If no codes → owner-proof path when implemented; else R3/R6
```

```bash
mymesh owner backup import --input ~/secure/owner-backup.sealed
mymesh owner show
# Carrier: restore vault from same sealed file + password
# then, if codes available:
mymesh mesh recover-master --code <hex>
mymesh mesh unlock
```

**Do not** send MMK recovery codes or MMK password to the phone ([MASTER-KEY.md](MASTER-KEY.md)).

---

## Runbook R6 — Lost MMK + owner + backup (host-local only)

**Goal:** Keep machines useful without remote policy root.

### What still works

- Host-local CLI on each machine (filesystem trust): `devices`, `grant`, `unlink`, `kick` (as implemented), `serve`, sessions for existing Trusted peers.
- Day-to-day shell/files/SSH between already-Trusted members.

### What does **not** work

- Unlock MMK / `mesh prove` / MRK-backed mesh API admin.
- `owner clear` / replace claim / `allow-claim` (need unlocked MMK).
- Prove mesh-destructive authority to remote callers.

### Options

1. **Find recovery codes** (offline printout from `mesh init`) → R4.
2. **Nuclear** re-init policy on hosts you control → R3; re-pair.
3. **Operate degraded** — no MMK — until you accept nuclear rekey.

**Prevention:** store recovery codes offline at init; export `owner-backup.sealed` to offline storage; use a password manager for MMK + backup passwords (separate secrets).

---

## Runbook ER — Enroll revoke (stolen / lost phone)

**Goal:** Stop a stolen Carrier from **driving** enrolled nodes. This is **not** owner clear and **not** MMK rotate.

### Threat context

- Enroll is **not** mesh ownership ([CARRIER-ADMIN-NEXT.md](CARRIER-ADMIN-NEXT.md), [THREATS.md](THREATS.md) **C8** / **C9**).
- Confirm-on-machine completes **pair** only — it does not write `enrollments.json`.
- `person_enrolled` can introduce / create-first-mesh / read this-node catalog; it **cannot** mutate grants or smash MMK.
- Standing last-mile sessions last **15 minutes**. Revoke does not kill an already-minted Bearer until it expires; re-enroll after revoke needs a new verified person sig.

### Steps (each enrolled node)

```bash
mymesh enroll list
# person_id  facet  drive  …

mymesh enroll revoke <person_id>
mymesh enroll list    # that person gone; can_drive false
```

HTTP equivalent (host-local or that person's `person_enrolled` / `mrk_proof`):

```bash
# loopback
curl -X DELETE http://127.0.0.1:17878/mesh/v1/enrollments/<person_id>
```

### Checklist

- [ ] Revoked on **every** box that listed the stolen phone (`enroll list`)
- [ ] Phone cannot `POST /enrollments` again without a new ceremony (different key after revoke is allowed)
- [ ] Optional: revoke guest grants the phone created ([Runbook G](#runbook-g--compromised-guest))
- [ ] Do **not** `owner clear` or `mesh init --force` solely because a phone was stolen
- [ ] Re-enroll the replacement phone with a verified `carrier-enroll-v1` sig (TOFU fp again)

### Related

- CLI: `mymesh enroll --help`
- Authz matrix: [CARRIER-ADMIN-NEXT.md](CARRIER-ADMIN-NEXT.md)
- Controls: [THREATS.md](THREATS.md) **C9**

---

## Runbook G — Compromised guest

**Goal:** End guest access immediately without rotating MMK or owner.

### Threat context

- Guest never holds MMK or person seed ([GUEST.md](GUEST.md), [MASTER-KEY.md](MASTER-KEY.md)).
- Guest may still hold residual host data on **their** device until wipe (continuity wipe **planned** — [THREATS.md](THREATS.md) **C4** partial).
- Active grants until revoked; sessions should deny revoked grants.

### Steps

```bash
mymesh grant list
# identify grant_id for the compromised guest → object host

mymesh grant revoke <grant_id>
mymesh grant list --all    # confirm revoked_at set

# Optional: drop bilateral trust on the object host
mymesh unlink <guest-device>

# If the peer was mistakenly onboarded as a full member:
mymesh kick <device>      # double confirmation; mesh-wide
```

### Checklist

- [ ] Grant revoked on object host
- [ ] No active guest sessions (reconnect denied)
- [ ] Guest not listed as Trusted member path (or kicked if mis-roled)
- [ ] Operator rotates any **host** secrets the guest could have seen (shell history, tokens in home dir) — **outside** MyMesh
- [ ] Do **not** rotate MMK solely because a guest was compromised (unless guest somehow obtained host filesystem access to `mesh-master.json` **and** password — then treat as MMK leak)

### Related

- Grant schema / revoke: [GRANTS.md](GRANTS.md)
- Guest isolation: [GUEST.md](GUEST.md)
- Residual wipe roadmap: [THREATS.md](THREATS.md) C4

---

## Runbook L — MMK leak / password rotate

**Goal:** Attacker may know the **MMK password** (or you suspect phishing / shared secret); reduce window of abuse.

### Case L1 — Password leaked; wrap file **not** stolen

You still control the hosts; attacker never obtained `mesh-master.json`.

```bash
mymesh mesh unlock
mymesh mesh rotate-master
# enter current (leaked) password, then a NEW strong password
mymesh mesh lock
mymesh mesh unlock   # verify new password
```

- **Same MRK** — admin keys unchanged; owner claim fingerprints unchanged.
- Old password no longer unwraps the file after rotate.
- Recovery codes **unchanged** (still valid).

### Case L2 — Password leaked **and** `mesh-master.json` may have been copied

Attacker can offline-unwrap MRK with the leaked password until you destroy that MRK.

```bash
# Prefer recovery that mints a NEW MRK (invalidates stolen wrap)
mymesh mesh recover-master --code <unused-recovery-hex>
# set a new password; old wrap + old MRK are dead

mymesh mesh unlock
mymesh owner show    # claim retained; new mrk_fingerprint / epoch
```

If **no** recovery codes remain:

- Owner-proof path when implemented; until then treat as **R3** if you must kill the old MRK, or accept risk if the stolen copy is unlikely.

### Case L3 — MMK unlocked cache left on a shared machine

```bash
mymesh mesh lock
# ensure mmk-runtime.json cleared; re-prompt policy is default
# do not enable OS keyring (not default; not productized as opt-in in alpha docs)
```

### Also rotate

- Owner **backup** password if stored in the same password manager entry as MMK (use separate secrets).
- Any remote Admin assignments you no longer trust: `mymesh devices revoke-admin <id>`.

---

## Runbook B — Restore owner from sealed backup (detail)

**Goal:** Recover person seed material and re-establish owner UX.

### On mesh host (blob custody)

| Action | Command |
|--------|---------|
| See claim + whether blob present | `mymesh owner show` |
| Copy blob off machine | `mymesh owner backup export --out PATH` |
| Install blob from offline media | `mymesh owner backup import --input PATH` |
| Seal seed (air-gap / lab) | `mymesh owner backup store --person-id … --seed-hex …` |

### Crypto facts

- KDF: Argon2id within S0 ranges; wrap: XChaCha20-Poly1305 ([MASTER-KEY.md](MASTER-KEY.md)).
- **MRK is not required** to decrypt the sealed person seed (**C3**).
- Password env helper for store: `MYMESH_BACKUP_PASSWORD` or `--password-file` / prompt.

### Phone restore

1. Export sealed file from a trusted host (or use offline copy created at claim time).
2. On Carrier: restore flow with file + backup password → person Keystore.
3. Re-open owner session; topology should show existing claim if `person_id` / pubkey match `mesh-owner.json`.

### If claim file is missing but backup exists

```bash
mymesh owner backup import --input ~/secure/owner-backup.sealed
# Restore phone from same blob, then re-claim with MMK authorization:
mymesh mesh unlock
mymesh owner allow-claim --secs 300
# Carrier or CLI claim with restored person keys
```

### If claim exists but backup missing

- Phone still works until lost; create a **new** sealed backup ASAP from Carrier or `owner backup store`.
- Missing backup does not invalidate the claim.

---

## Prevention checklist

| Practice | Why |
|----------|-----|
| Print / store **MMK recovery codes** offline at `mesh init` | Only implemented path to recover lost MMK password today |
| Separate passwords: MMK vs owner backup | Dual authority; one leak should not unlock both |
| Export `owner-backup.sealed` to offline storage after claim | R1 / R5 |
| `mesh lock` on shared hosts | Clear host-local MRK cache |
| Prefer pair v2 confirm over LAN decide on hostile networks | [DEMO-PAIR.md](DEMO-PAIR.md) · [THREATS.md](THREATS.md) C1–C2 |
| Revoke guest grants promptly | Runbook G · [GRANTS.md](GRANTS.md) |
| Revoke enrollments on stolen phones | Runbook ER · [THREATS.md](THREATS.md) **C9** |
| Do not put MMK / recovery codes on the phone | Normative forbidden ([MASTER-KEY.md](MASTER-KEY.md)) |

---

## Related

| Doc | Topic |
|-----|--------|
| [MASTER-KEY.md](MASTER-KEY.md) | MMK crypto, recovery matrix contract, owner claim patterns |
| Carrier `docs/OWNERSHIP.md` | Phone claim / sealed backup restore UX (Carrier repo) |
| [SECURITY.md](SECURITY.md) | Trust model, dual authority summary |
| [THREATS.md](THREATS.md) | C1–C7 + Wave F C8–C13, backup theft, MMK lockout, enroll revoke |
| [DEMO-PAIR.md](DEMO-PAIR.md) | Re-pair after nuclear recovery |
| [GUEST.md](GUEST.md) · [GRANTS.md](GRANTS.md) | Guest isolation + revoke |
| [USAGE.md](USAGE.md) | Day-to-day CLI |
| [CARRIER-NEXT.md](CARRIER-NEXT.md) | Full S0–S9 design; S9 runbook list |
| [JOIN.md](JOIN.md) | Link / accept membership |
