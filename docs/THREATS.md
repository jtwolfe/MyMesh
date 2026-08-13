# Threat model & S9 control checklist

| Field | Value |
|-------|--------|
| **Audience** | Operators, reviewers, implementers |
| **Status** | Living threat model aligned with [CARRIER-NEXT.md](CARRIER-NEXT.md) §S9 — **not** a formal audit |
| **Related** | [SECURITY.md](SECURITY.md) (operator model), [RECOVERY.md](RECOVERY.md) (ops runbooks), [CARRIER-ADMIN-NEXT.md](CARRIER-ADMIN-NEXT.md) (Wave F C8–C13), [PAIR-V2.md](PAIR-V2.md), [MASTER-KEY.md](MASTER-KEY.md), [GRANTS.md](GRANTS.md), [GUEST.md](GUEST.md), [DEMO-PAIR.md](DEMO-PAIR.md) |

---

## Scope

MyMesh is a **personal mesh**: machines you explicitly link, plus optional Carrier phone as a **control-plane UI** (not an iroh mesh peer). This document covers:

1. Pair / join (v1 LAN HTTP + v2 dual-scan + confirm-on-machine)
2. Mesh master key (MMK) and sealed owner backup
3. Guest grants and residual data
4. Mesh API topology authenticity
5. Multi-identity facets (S7 design)
6. Brute-force / abuse of decide and unwrap surfaces

**Out of scope for this checklist:** OS compromise of a Trusted peer (assumed powerful), public multi-tenant pair cloud, formal crypto proofs.

---

## Trust boundaries

```text
┌─────────────┐     pair bootstrap / confirm      ┌──────────────────┐
│   Carrier   │ ──── QR / codes / optional HTTP ──│  MyMesh agent    │
│  (phone UI) │                                    │  (host / joiner) │
└─────────────┘                                    └────────┬─────────┘
                                                            │ iroh QUIC
                                                            ▼
                                                   ┌──────────────────┐
                                                   │ peer agents      │
                                                   │ (Trusted only)   │
                                                   └──────────────────┘
```

| Boundary | What crosses it | Trust assumption |
|----------|-----------------|------------------|
| Phone ↔ operator eyes | QR, confirm codes | Human verifies dual fingerprints before accept |
| Phone ↔ agent HTTP (LAN v1 / direct ep) | Bearer token, decide | LAN may be hostile; prefer confirm path (zero phone HTTP) |
| Joiner ↔ host (iroh) | Signed JoinRequest / Accept | Possession of device key; arm window required |
| Mesh API (carrier process) | Challenge → session → topology | Cleartext LAN without mesh session cannot call topology |
| Disk at rest | `mesh-master.json`, `owner-backup.sealed`, pair sessions | Password / Argon2id; file mode 0600 |

---

## Threat catalog (CARRIER-NEXT §Security)

| Threat | Impact | Primary control | Slice |
|--------|--------|-----------------|-------|
| Attacker joins as device | Shell / files / TCP as agent user | Dual-scan fps; short arm; **C2** bind joiner; revoke | S2, S5 |
| Session fixation on pair | Accept wrong / replay session | **C1** token + sid + nonce + TTL | S1–S2 |
| LAN MITM pair HTTP | Bootstrap token theft | Confirm path without phone HTTP; optional TLS pin (S9) | S2, S9 |
| Stolen sealed backup | Person seed if weak password | **C3** Argon2id AEAD; **C7** unwrap rate limit | S4, S9 |
| Stolen mesh-master + password | Full mesh admin | Argon2id wrap; recovery codes; rotate | S3 |
| Guest retains host data | Privacy after share ends | **C4** grant revoke + continuity wipe | S5, S8 |
| Guest learns full roster | Mesh membership leak | No `MembershipSnapshot` for guest | S5 |
| Malicious / forged topology | Wrong trust UI | **C5** mesh-auth session; optional snapshot sig | S6, S9 |
| Cross-facet bleed | Work ↔ personal leak | **C6** separate keys + allowlists | S7 |
| Confirm / decide brute force | Wrong accept / token grind | **C7** rate limits; single-use confirm | S2, S9 |
| Confirm shoulder-surf | Wrong accept | TTL; single-use; dual fps shown first | S2 |
| MMK lost, owner alive | Admin lockout | `recover-master --code` (today); owner-proof planned — [RECOVERY.md](RECOVERY.md) R4 | S3/S4 |
| Owner lost, MMK alive | Person lockout | MMK clear owner; new claim — [RECOVERY.md](RECOVERY.md) R2 | S4 |
| Audit secret leak | Tokens in logs | Redaction (Carrier S9) | S9 |
| Compromised Trusted peer | Full agent-user power | Unlink / kick; no remote-user isolation yet | alpha |
| Enroll confused with owner/destroy | Wipe MMK / claim by accident | **C8** create only if uninited; claim MMK-gated | Wave F |
| Stolen phone drives enrolled nodes | Remote admin of household boxes | **C9** L2 drive ops; enroll revoke; 15 m session | Wave F |
| Gateway confused deputy | A forwards admin meant for B | **C10** no iroh admin forward; last-mile = target | Wave F |
| Mailbox operator reads ops | Admin payload leak | **C11** required seal to device pk; opaque store | Wave F |
| Overlap roster leak | Dest mesh members visible | **C12** guest path only; refuse smash; extra member 501 | Wave F |
| Last-hint IP leak | LAN URL in UI/logs | **C13** never log/render host; HintBlob wrap | Wave F |

---

## S9 control checklist (C1–C7)

Normative IDs from [CARRIER-NEXT.md](CARRIER-NEXT.md) §S9. Status reflects **this MyMesh tree** (Carrier phone app is a separate repo).

| ID | Threat | Control | Status | Where |
|----|--------|---------|--------|-------|
| **C1** | Session fixation | Bootstrap **token** (hash-only on disk) + **sid** + 16B **nonce** + arm **TTL** | **Implemented** (pair v2) | `mymesh-core` `PairSessionStore`, [PAIR-V2.md](PAIR-V2.md) |
| **C2** | Wrong joiner accept | Bind **joiner_did** before decide; confirm code = HMAC over sid + joiner + resident + nonce | **Implemented** | `pair_confirm.rs`, `apply_pair_confirm` / `not_bound` fail-closed |
| **C3** | Backup theft | Password **Argon2id** → AEAD (XChaCha20-Poly1305) over person seed; MRK not required to decrypt | **Implemented** | `mymesh-crypto` `seal_owner_backup` / `owner-backup.sealed`; MMK wrap is separate Argon2id (S3) |
| **C4** | Guest residual | **Grant revoke** (store + wire) + **continuity wipe** on leave | **Partial** | Revoke: `GrantStore::revoke`, `GrantRevoke` gossip — **done**. Continuity pack wipe host path (S8/E4) — **done** (materialize/wipe/status + best-effort erase). Carrier leave UX is E5 |
| **C5** | Topology MITM | Topology only over **mesh-auth** session; optional host **snapshot_sig** | **Partial** | Challenge + Bearer session + filtered topology — **done** (`mesh_api.rs`). `snapshot_sig_hex` always `null` until optional S9 pin |
| **C6** | Facet bleed | Identity facet + location **allowlists** enforced on grants | **Planned** (S7) | Fields exist on `GrantConstraints`; **not enforced** until Wave E / PR E2 |
| **C7** | Decide brute force | Rate limits on decide/confirm, mesh auth challenge, backup unwrap, grant mutate | **Planned** (S9 / PR D1) | Defaults below; metrics names reserved in design — **not wired** in this tree yet |

### C1 — Session fixation (detail)

**Threat:** Attacker reuses or injects a pair session so the host accepts a joiner bound to the wrong bootstrap.

**Control:**

- Each arm creates a unique **sid** (ULID) and **32B bootstrap token** (stored as SHA-256 hash only in session JSON; raw token in mode-0600 sidecar for local confirm).
- Required **16-byte nonce** in v2 QR / status / SessionDecision (missing nonce → parse fail).
- Session **`until` TTL**; expired → `Expired` phase; open phases only `Armed` \| `Bound`.

**Honest residual:** v1 pair without nonce remains available only via `mymesh carrier --pair-v1` (compat escape); product default is pair/v2 (sid+nonce+TTL).

### C2 — Wrong joiner accept (detail)

**Threat:** Host confirms accept while a different device completed JoinRequest, or accepts before any joiner binds.

**Control:**

- Confirm HMAC material includes **joiner_did** and **resident_did** (see [PAIR-V2.md](PAIR-V2.md)).
- Unbound confirm → **`not_bound`** closed (no hang, no accept).
- `bind_joiner` is sticky: rebinding a different device id fails.

**Honest residual:** Operator still must verify dual fingerprints; crypto does not prove the joiner OS is clean.

### C3 — Backup theft (detail)

**Threat:** Offline attacker steals `owner-backup.sealed` (or phone export) and recovers the person seed.

**Control:** Password-based Argon2id KDF within S0 parameter ranges + AEAD; wrong password fails closed. File mode 0600 when written under agent Paths.

**Honest residual:** Weak passwords remain offline-attackable until **C7** unwrap rate limits and UI guidance; Argon2id raises cost but does not replace a strong password. MMK file (`mesh-master.json`) is a **separate** root — steal both + passwords for full dual-authority compromise.

### C4 — Guest residual (detail)

**Threat:** After share ends, guest device still has grants/caps or host retains guest-owned continuity data.

**Control:**

| Piece | Status |
|-------|--------|
| `GrantStore` revoke + `revoked_at` | Implemented |
| Session `allows()` denies revoked/expired guest caps | Implemented |
| `GrantRevoke` control message | Implemented |
| Guest join without full membership snapshot | Implemented (S5 / C1b path) |
| Continuity materialize + wipe_token wipe | **Implemented** (S8 / E4): `POST /mesh/v1/continuity/materialize|wipe`, `GET .../status`; host store under `continuity/<pack_id>/`; best-effort zero+unlink |

### C5 — Topology MITM (detail)

**Threat:** LAN attacker serves forged mesh roster to Carrier or a client.

**Control:**

- `GET /mesh/v1/topology` requires `Authorization: Bearer` mesh session.
- Session minted only after challenge-response (`device_member` / `person_owner` / `mrk_proof` / short-lived `pair_read`).
- Guests / pair_read get **minimal** topology, not full member roster (Wave C PR C4 topology filter: guest `device_member` → self+object host, mint-pinned `minimal_roster`; `grants_summary` for person_owner / mrk_proof / Admin-or-own device_member).

**Planned:** Optional `snapshot_sig_hex` = host device Ed25519 over canonical topology body for TOFU/pinning displays. Until then, authenticity = possession of mesh session keys on the carrier process channel.

### C6 — Facet bleed (detail)

**Threat:** Work facet grant used under personal identity (or vice versa); location constraints ignored.

**Control (S7 design):** Per-facet keys on Carrier + `GrantConstraints.identity_facet` / `location_allowlist` enforced on MyMesh session path.

**Today:** Constraints may be **stored** on grants; `allows()` does **not** evaluate facet or location. Do not claim multi-identity isolation until Wave E exit.

### C7 — Decide / unwrap brute force (detail)

**Threat:** Online grinding of confirm codes, pair decide Bearer, mesh auth challenges, or backup passwords.

**Designed defaults** ([CARRIER-NEXT.md](CARRIER-NEXT.md) §S9):

| Endpoint / event | Limit | Metric name |
|------------------|-------|-------------|
| pair decide / confirm | 10 / min / token | `pair_decide_total{result}` |
| pair status unauth | 60 / min / ip | `pair_status_total` |
| mesh auth challenge | 30 / min / ip | `mesh_auth_challenge_total` |
| backup unwrap attempts | 5 / 15 min / person_id | `owner_backup_unwrap_total{result}` |
| grant mutate | 30 / min / session | `grant_mutate_total` |

**Today:** Confirm codes are single-use once consumed and TTL-bound; **no** process-wide rate-limit middleware matching the table (PR **D1**). Existing `metrics` paths are peer host-stats, not these counters.

---

## Wave F control checklist (C8–C13)

Normative IDs from [CARRIER-ADMIN-NEXT.md](CARRIER-ADMIN-NEXT.md). Status is this MyMesh tree after F1–F10.

| ID | Threat | Control | Status | Where |
|----|--------|---------|--------|-------|
| **C8** | Enroll ≠ owner confused for destroy | Separate ceremonies; `POST /meshes` only if no `mesh-master.json`; claim still MMK-gated | **Implemented** | `meshes_create` 409 `mesh_already_inited`; `apply_first_mesh_init` |
| **C9** | Stolen phone drives enrolled nodes | L2 on Carrier drive ops; `person_enrolled` cannot mutate grants; enroll revoke CLI + `DELETE /enrollments`; session 15 m | **Implemented** | `enrollments_revoke`, `mymesh enroll revoke`, `require_grants_mutate_authz` |
| **C10** | Gateway confused deputy | Wave F does **not** iroh-forward admin; execute on last-mile **target** after person sig; miss → `no_last_mile_to_joiner` | **Implemented** | `introduce_op`; no `OpenChannel(Admin)` |
| **C11** | Mailbox operator reads ops | Required seal to device pk; opaque store; TTL prune; no body logs | **Implemented** | `seal_admin_envelope`; `ADMIN_MAILBOX_TTL_SECS` |
| **C12** | Overlap roster leak | Guest path only; extra `role=member` → 501; refuse `adopt_mesh_id` when extras exist | **Implemented** | `MembershipStore::add_row` / `blocks_adopt`; topology still this-mesh members |
| **C13** | Last-hint IP leak | Never log/render last-mile URL; HintBlob wrap; Advanced only for plaintext host | **Implemented** | TUI redact; Carrier `LastMile` Debug; QR `host=` stays private hint |

### C8 — Enroll ≠ owner / destroy (detail)

**Threat:** Phone “create mesh” or enroll UX is mistaken for owner claim or `mesh init --force`, wiping MMK.

**Control:** Create is first-init only (`mesh-master.json` exclusive). Second create is **409** `mesh_already_inited`. Owner claim remains MMK- or window-gated. Confirm-on-machine completes **pair**, not enroll.

### C9 — Stolen phone drives enrolled nodes (detail)

**Threat:** Lost phone with an enrolled person key `POST /admin/rpc` / introduce / create on household boxes.

**Control:** Drive ops need last-mile + person sig + `can_drive`. `person_enrolled` cannot mutate grants. Operator runs `mymesh enroll revoke <person_id>` (or `DELETE /enrollments/{id}`) on **each** enrolled node. Mesh sessions expire in 15 minutes.

### C10 — Gateway confused deputy (detail)

**Threat:** Phone reaches enrolled A and asks A to admin B over iroh.

**Control:** Wave F never opens `ChannelKind::Admin`. Introduce last-mile is always the **joiner**. If the phone cannot reach B → `no_last_mile_to_joiner` (confirm on B or mailbox).

### C11 — Mailbox operator (detail)

**Threat:** Self-host mailbox operator reads introduce/enroll JSON.

**Control:** PUT body is `AdminSealPayload` sealed to the target device pk. Store is opaque bytes. Lanes prune after `ADMIN_MAILBOX_TTL_SECS` (15 min). Raw envelope is not a seal.

### C12 — Overlap roster leak (detail)

**Threat:** Guest overlap or smash `adopt_mesh_id` exposes dest-mesh members.

**Control:** Extra catalog rows are **guest** only this wave. Extra `role=member` → 501 / `not_implemented` (F8b). `has_extra_rows` blocks foreign `adopt_mesh_id`. Topology members stay the **primary** mesh roster.

### C13 — Last-hint IP leak (detail)

**Threat:** LAN `host=` from QR appears in TUI, logs, or Carrier chrome.

**Control:** `host=` stays in the QR (private last-mile hint; stripping is wontfix). Product chrome never renders `192.168.` / `:17878`. Errors truncate hosts. HintBlob wrap for standing inventory.

---

## Rate limits & hardening backlog (S9)

| Item | PR / slice | Notes |
|------|------------|-------|
| Rate limits + metric names | **D1** | Implements **C7** |
| Optional TLS pin `tlspin=` on direct ep | **D2** | Wire + parse + fail-closed verify hook (MyMesh); Carrier release denies cleartext; client TLS stack wiring is **D3** |
| Persistent Carrier audit (redacted) | **D3** | Carrier repo |
| This document + SECURITY cross-link | **D4** | This PR |
| Carrier default QR v2 | **D5** | **Done** — default v2; `--pair-v1` escape |
| Facet enforce | **E2** | Completes **C6** |
| Continuity wipe | **E4–E5** | Completes **C4** residual path |

---

## Operator quick rules

1. Prefer **v2 dual-scan + confirm** over LAN decide when the network is untrusted.
2. Use a **strong password** for owner backup and MMK; treat sealed files as sensitive.
3. **Revoke grants** and unlink/kick devices promptly when a share ends or a peer is suspect.
4. Do not rebind SOCKS or carrier HTTP to `0.0.0.0` without understanding exposure ([SECURITY.md](SECURITY.md)).
5. Treat every **Trusted** peer with Terminal/Files/TCP as equivalent to local user access on the agent host.
6. Store **MMK recovery codes** offline at `mesh init`; export sealed owner backup — full procedures in **[RECOVERY.md](RECOVERY.md)**.
7. Lost/stolen enrolled phone: `mymesh enroll revoke <person_id>` on **each** node (**C9**). Confirm-on-machine is pair-only — it does not enroll.

---

## See also

- [SECURITY.md](SECURITY.md) — alpha trust model, privilege, reporting  
- **[RECOVERY.md](RECOVERY.md)** — dual-authority recovery runbooks (lost phone/MMK, guest, enroll revoke, rotate, backup)  
- [CARRIER-ADMIN-NEXT.md](CARRIER-ADMIN-NEXT.md) — Wave F C8–C13 + authz matrix  
- [CARRIER-NEXT.md](CARRIER-NEXT.md) — full S0–S9 design, control checklist source  
- [PAIR-V2.md](PAIR-V2.md) · [DEMO-PAIR.md](DEMO-PAIR.md) · [MASTER-KEY.md](MASTER-KEY.md)  
- [GRANTS.md](GRANTS.md) · [GUEST.md](GUEST.md) · [JOIN.md](JOIN.md)
