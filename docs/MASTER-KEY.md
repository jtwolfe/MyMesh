# Mesh master key (MMK) — S0 contract

| Field | Value |
|-------|--------|
| **Status** | Normative contract freeze (S0) |
| **Slice** | S3 implements; this doc freezes crypto ranges, file shape, authority, recovery |
| **Source** | [CARRIER-NEXT.md](CARRIER-NEXT.md) §S3, dual authority, recovery matrix |
| **Related** | [RECOVERY.md](RECOVERY.md) (ops runbooks), [GRANTS.md](GRANTS.md), [GUEST.md](GUEST.md), [JOIN.md](JOIN.md), [SECURITY.md](SECURITY.md), [THREATS.md](THREATS.md), [PAIR-V2.md](PAIR-V2.md) |

---

## Role

The **mesh master key (MMK)** is the password/key that wraps the **mesh root key (MRK)**. MMK/MRK is the **root of mesh policy**.

**Authority invariants (normative):**

1. **MMK is root of mesh policy.** For mesh-destructive ops (clear owner, force rotate owner, emergency kick all, re-init mesh identity of policy files), MMK proof **wins** over person-owner claim and over remote Admin cap.
2. **Owner is portable person binding** (Carrier / `mesh-owner.json`), preferred for day-to-day remote admin after claim exists — **subordinate** to MMK for mesh-destructive ops. See owner claim in [CARRIER-NEXT.md](CARRIER-NEXT.md) §S4 (Carrier repo mirrors OWNERSHIP).
3. **Host-local CLI** (process with access to agent `Paths` data dir) can always administer **this node** (filesystem = root of trust on that machine). Distinct from remote Admin cap.
4. **Remote Admin cap** (`Capability::Admin` on a Trusted **member** device) enables remote mesh API admin when granted; alpha.1 never grants it by default and never checks it in session path.
5. Compromising a guest device never yields MMK or person seed. Sealed owner backup without password does not yield person seed.

MyMesh **stands alone**: MMK + CLI link/accept work with **no Carrier** required.

---

## Cryptography (S0 freeze)

| Item | Choice |
|------|--------|
| KDF | Argon2id within parameter ranges below |
| Wrap | XChaCha20-Poly1305 over 32-byte **MRK** |
| MRK HKDF labels | `mymesh/mrk/admin-sign`, `mymesh/mrk/admin-mac` — **not** person-backup key |
| Sealed person backup | **Independent** password-AEAD (S4); MRK does **not** encrypt person seed |
| Recovery codes | 256-bit (or 24 words); hash stored; print once at `mesh init` |

### Argon2id parameter ranges (normative)

| Use | m (KiB) | t | p | Notes |
|-----|---------|---|---|--------|
| MMK wrap | 64_000–256_000 | 2–4 | 1–4 | Pick defaults in S3 impl; stay in range |
| Owner backup | 64_000–256_000 | 2–4 | 1–4 | Independent of MMK |

Defaults are implementation choices within these ranges (not frozen as single numbers in S0).

---

## On-disk: `mesh-master.json`

Mode **0600** under agent `Paths` data dir.

```json
{
  "kdf": "argon2id",
  "kdf_params": { "m": 65536, "t": 3, "p": 1 },
  "salt": "<b64>",
  "wrap_alg": "xchacha20poly1305",
  "nonce": "<b64>",
  "wrapped_mrk": "<b64>",
  "mrk_fingerprint": "<8 hex>",
  "recovery_code_hashes": ["<hex>", "..."],
  "created_at": "...",
  "rotated_at": null
}
```

- **MRK** exists only in process memory when unlocked (default).
- **`mrk_fingerprint`**: short display/bind value; also written into `mesh-owner.json` on claim; updated on `recover-master` without clearing person claim (KD28).

Optional related fields on mesh/owner files:

| File | Field | Notes |
|------|-------|--------|
| `mesh.json` | `mrk_fingerprint?` | Optional mirror for topology |
| `mesh-owner.json` | `mrk_fingerprint`, `mrk_epoch` | Epoch increments on recover-master |

---

## CLI (S3 — implemented unless noted)

```bash
mymesh mesh init                 # password + print recovery codes once
mymesh mesh unlock | lock | status
mymesh mesh rotate-master        # re-wrap same MRK under new password
mymesh mesh recover-master --code <recovery>
mymesh mesh recover-master --owner-proof  # flag exists; challenge/sign not yet wired
```

Owner claim + sealed backup CLI: `mymesh owner allow-claim|claim|show|clear|backup …` (S4). Full recovery procedures: [RECOVERY.md](RECOVERY.md).

### Unlock policy (normative — KD30)

| Mode | Default? | Behavior |
|------|----------|----------|
| **Re-prompt** | **Yes** | Agent start / after lock: operator enters MMK password (or recovery). MRK only in process memory. |
| **Opt-in OS keyring** | No | User explicitly enables store-of-unwrapped-MRK or password in platform keyring for unlock-on-boot / unlock-on-serve. Document threat: physical access to unlocked OS session. Disable returns to re-prompt. |

Never enable keyring by default in `mesh init`.

### After `recover-master` (normative)

1. New MRK wrapped with new password (or re-entered password); old wrap invalidated.
2. If `mesh-owner.json` exists: update `mrk_fingerprint` to new value; set `mrk_epoch += 1` if field present (default 0→1). **Do not** clear person claim — ownership is person binding, not MRK bytes.
3. Topology `mrk_fingerprint` comes from live mesh-master / mesh state after unlock.
4. Sealed owner backup unchanged (password-AEAD independent of MRK).

---

## Authorization matrix

| Actor | Can |
|-------|-----|
| Host-local CLI (data dir access) | Always configure this node; write grants/kick local; unlock MMK interactively |
| MRK unlocked / `mrk_proof` | Mesh-destructive + remote admin API |
| Person owner session | Day-to-day remote admin; **not** clear owner without MMK (or recover-master path) |
| Device with `Capability::Admin` | Remote grant/kick as allowed; not clear MMK |
| Device without Admin | Session caps only; topology read if member |

### Mesh-destructive ops (require MMK / MRK proof)

- Clear / replace owner claim
- Emergency kick all / re-init policy identity files
- Force rotate ownership of policy files

### Mesh API auth methods (S0 freeze)

| Method | Key | Issues |
|--------|-----|--------|
| `mrk_proof` | MRK-derived admin Ed25519 or HMAC | Admin / destructive |
| `person_owner` | Person Ed25519 after claim | Owner UX |
| `device_member` | Device Ed25519 of Trusted **member** MyMesh node | Topology/CLI on that machine; **not** Carrier phone |
| `pair_read` | Bootstrap-bound read session post dual-scan | Carrier phone **minimal** topology only; not full household |

---

## Recovery matrix (dual authority)

**Ops runbooks (commands, checklists, honesty about CLI gaps):** **[RECOVERY.md](RECOVERY.md)**.

| Lost | Still have | Recovery |
|------|------------|----------|
| Phone | Sealed backup + password | Restore person on new phone; re-auth as owner |
| Phone + backup password | MMK | MMK clears/replaces owner; new claim |
| Phone + backup + MMK | — | Nuclear: new mesh / re-pair devices; old mesh_id abandoned |
| MMK password | Recovery codes (today) / owner claim + phone (planned `--owner-proof`) | `mymesh mesh recover-master --code` (**implemented**); `--owner-proof` signs challenge when wired — new MRK; update `mesh-owner.json` `mrk_fingerprint` (claim remains valid) |
| MMK + owner phone | Sealed backup on disk + password | Restore phone first, then recover-master |
| MMK + owner + backup | Trusted member with host-local CLI | Host-local can still run node; **cannot** prove remote MMK; export recovery codes at init recommended; else nuclear re-init policy files |

**MMK recovery codes** at `mesh init`: 256-bit printed once (or 24 words), separate from daily password; hashes in `mesh-master.json` for `recover-master --code`. Owner proof path is additional when claim exists (**flag present; challenge/sign not yet wired** — see [RECOVERY.md](RECOVERY.md) R4).

---

## Admin capability migration (existing meshes)

1. **Host-local CLI always retains node admin** (filesystem trust).
2. **Remote/API admin** requires Admin cap **or** MMK proof **or** owner session.
3. **Upgrade migration:** on first load after upgrade, if `mesh-master.json` missing, do not break sessions. When `mesh init` runs, creator device record gets `capabilities` including `Admin` and `mesh_role=member`.
4. **Existing Trusted devices:** keep capabilities as stored (**no** Admin auto-grant). Operators use host-local CLI or MMK after init to `mymesh devices grant-admin <id>`.
5. **Default grant remains without Admin** (matches alpha.1 `Capability::all()` = terminal/files/desktop/tcp — Admin defined but not in default grant).

See [JOIN.md](JOIN.md) and [SECURITY.md](SECURITY.md).

---

## Owner claim and MMK (preview; S4)

Owner claim **requires MMK authorization on the mesh agent** (policy root). Phone never receives or stores MMK material; phone sends **person signature only**.

Patterns (both supported; first preferred):

| Pattern | How |
|---------|-----|
| Agent co-sign | Operator has `mesh unlock` so MRK is in serve memory; phone POSTs person-signed claim; agent co-signs locally. If locked → `403 mmk_locked`. |
| CLI claim window | `mymesh owner allow-claim --secs 300` (MMK unlocked or recovery at mint); window file is MMK-authorized capability. |
| CLI-only claim | `mymesh owner claim --person-pubkey … --sig-file …` on machine with MMK unlocked. |

**Forbidden:** sending MMK password, recovery codes, or MRK bytes to the phone.

Canonical owner-claim preimage (S0 golden):

```text
carrier-mesh-owner-v1 || u16le(len) || mesh_id_utf8
  || u16le(len) || person_id_utf8
  || person_pk_32
  || mrk_fingerprint_utf8
  || i64le(ts_unix)
```

---

## Independence

| Mode | MMK |
|------|-----|
| MyMesh only | Required path for mesh policy root after S3; CLI admin without phone |
| Carrier + MyMesh | Preferred UX for owner claim; MMK still root for destructive ops |

---

## Explicit non-goals (this contract)

- Final Argon2id tunables outside the ranges above
- Phone-held MMK or MRK
- Auto-enabling OS keyring at init
- Treating device `mesh_role` as `owner` (person ownership is only in `mesh-owner.json`)

---

## See also

- [RECOVERY.md](RECOVERY.md) — dual-authority recovery runbooks (lost phone/MMK, guest, rotate, sealed backup)
- [CARRIER-NEXT.md](CARRIER-NEXT.md) — full S0–S9 design
- [GRANTS.md](GRANTS.md) — grant schema; issued_by may be MasterKeyProof
- [GUEST.md](GUEST.md) — guests never hold MMK
- [PAIR-V2.md](PAIR-V2.md) — pair control plane (orthogonal to MMK in Wave A)
- [JOIN.md](JOIN.md) — member join; Admin migration note
- [SECURITY.md](SECURITY.md) · [THREATS.md](THREATS.md) — trust model + C1–C7
- Carrier repo: `docs/OWNERSHIP.md` — phone claim / restore UX
