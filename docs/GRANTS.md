# Grants — S0 contract

| Field | Value |
|-------|--------|
| **Status** | Normative contract freeze (S0) · **store + `allows()` (C1) · HTTP grants API (C2)** |
| **Slice** | S5: GrantStore + session enforcement (this doc); guest join wire delta in C1b; mesh/v1 grants in C2 |
| **Source** | [CARRIER-NEXT.md](CARRIER-NEXT.md) § grant model, §S5 |
| **Related** | [GUEST.md](GUEST.md), [MASTER-KEY.md](MASTER-KEY.md), [JOIN.md](JOIN.md), [SECURITY.md](SECURITY.md) |

---

## Role

A **Grant** is first-class authorization: subject device, object, role, capabilities, and constraints. It is federation-ready in shape; Wave C (S5) implements **object = one Device**, **role = guest**.

**Person ownership is not a grant role.** Owner lives only in `mesh-owner.json` / topology `owner` object. Device mesh roles are `member` | `guest` only (never `owner` on a device). See [GUEST.md](GUEST.md) and [MASTER-KEY.md](MASTER-KEY.md).

---

## Grant JSON schema (S0 golden)

```json
{
  "grant_id": "<ULID>",
  "mesh_id": "<UUID>",
  "subject_device_id": "<DeviceId hex or canonical bytes encoding>",
  "object": {
    "kind": "device",
    "device_id": "<DeviceId>"
  },
  "role": "guest",
  "capabilities": ["terminal", "files", "desktop", "tcp"],
  "constraints": {
    "not_after": null,
    "max_sessions": null,
    "location_allowlist": null,
    "identity_facet": null
  },
  "issued_by": {
    "kind": "device_id | person_id | master_key_proof",
    "value": "..."
  },
  "issued_at": "<RFC3339>",
  "revoked_at": null
}
```

### Field notes

| Field | Normative |
|-------|-----------|
| `grant_id` | ULID |
| `mesh_id` | Mesh UUID |
| `subject_device_id` | Who receives access |
| `object` | S5: **Device only**. Later: Mesh \| Service (federation) |
| `role` | `member` \| `guest` — **not** `owner` |
| `capabilities` | Subset of `terminal`, `files`, `desktop`, `tcp`, `admin` |
| `constraints.not_after` | Optional expiry |
| `constraints.max_sessions` | Optional session cap |
| `constraints.location_allowlist` | S7 thin; optional |
| `constraints.identity_facet` | S7: `personal` \| `work`; optional |
| `issued_by` | DeviceId \| PersonId \| MasterKeyProof |
| `revoked_at` | Set on revoke; grant becomes inactive |

### Rust-shaped sketch (non-binding syntax; wire is JSON)

```text
Grant {
  grant_id: ULID,
  mesh_id: UUID,
  subject_device_id: DeviceId,
  object: Device | Mesh | Service,   // S5: Device only
  role: member | guest,              // NOT owner
  capabilities: [terminal, files, desktop, tcp, admin],
  constraints: {
    not_after: Option<DateTime>,
    max_sessions: Option<u32>,
    location_allowlist: Option<[LocationTag]>,
    identity_facet: Option<personal|work>,
  },
  issued_by: DeviceId | PersonId | MasterKeyProof,
  issued_at: DateTime,
  revoked_at: Option<DateTime>,
}
```

---

## On-disk: `grants.json`

Mode **0600** under agent `Paths` (`Paths::grants_file()`).

**Implementation (C1):** map keyed by `grant_id`:

```json
{
  "grants": {
    "<ULID>": { /* Grant object — field shapes above */ }
  }
}
```

Rust: `mymesh_core::{GrantStore, Grant, allows}`. Session paths use `allows(devices, grants, local_id, peer, cap)`.

---

## S5 scope (first implementation)

| Constraint | Value |
|------------|-------|
| Object | **One Device** (the host being shared) |
| Role | **`guest`** |
| Roster | Guests do **not** receive mesh-wide `MembershipSnapshot` — see [GUEST.md](GUEST.md) |
| Facet / location | Enforced when present (S7); ignored if absent in S5 |

---

## Session enforcement

```text
allows(peer, cap):
  if peer.trust != Trusted: deny
  if peer.mesh_role == Guest:
    require active Grant covering this node as object with cap
    check not_after, facet constraints
  else:
    peer.capabilities.contains(cap)  // member path (alpha.1)
```

- **Active grant** = `revoked_at` is null and `not_after` not expired.
- Guest caps come from the Grant, not from a full mesh Admin path.
- Other mesh members (non-object hosts) deny guest sessions by default.

---

## CLI / API

### CLI (C1 — host-local)

```bash
mymesh grant create --to <guest> [--on <device>] --caps terminal,files --days 7
mymesh grant list [--json] [--all]
mymesh grant revoke <grant_id>
```

- Host-local CLI always may mutate `grants.json` (filesystem trust / `AdminAuthority::HostLocal`).
- `--on` defaults to **this node** (object host).
- `--to` accepts linked name/alias/prefix **or** bare 64-hex device id (guest may not be linked yet).
- Guest grants **reject** `admin` capability (product policy).
- `list` shows active grants by default; `--all` includes revoked/expired.

### HTTP (C2 — landed)

Served on the carrier mesh API (`/mesh/v1/*`), same `Paths` / `GrantStore` as CLI.

```text
POST /mesh/v1/grants              # create guest grant
GET  /mesh/v1/grants[?all=true]   # list (active only by default)
POST /mesh/v1/grants/{id}/revoke  # set revoked_at
```

All three require `Authorization: Bearer <mesh session>` (fail closed: 401 without session).

**Create body:**

```json
{
  "subject_device_id_hex": "<64-hex DeviceId>",
  "object_device_id_hex": null,
  "capabilities": ["terminal", "files"],
  "days": 7
}
```

- `object_device_id_hex` optional — defaults to **serving host**.
- `capabilities`: subset of `terminal` | `files` | `desktop` | `tcp` (`admin` rejected).
- `days` optional → `constraints.not_after`.
- Response: grant object (201); `issued_by` reflects auth method (`person_id` | `master_key_proof` | `device_id`).

**List:** `{ "grants": [ /* Grant */ ] }`. Active only unless `?all=true`.

**Revoke:** returns grant with `revoked_at` set (idempotent if already revoked). 404 `grant_not_found` if missing.

### Authz for grant mutate / list

| Actor | Allowed |
|-------|---------|
| `person_owner` session | Yes |
| `mrk_proof` | Yes |
| `device_member` with Admin | Yes |
| Serving host `device_member` (agent identity) | Yes |
| Host-local CLI | Yes (filesystem; not HTTP) |
| `device_member` without Admin | No (`admin_required`) |
| Guest (`mesh_role=guest`) | No (`guest_forbidden`) |
| `pair_read` / unauthenticated | No |

---

## Revoke vs kick

| | Grant revoke | Kick |
|--|--------------|------|
| Scope | One grant / object access | Mesh-wide member removal |
| Guest | **Primary tool** | N/A (guest not full member) |
| Member | Rare (if grant-shaped later) | **Primary** |

Revoke effects:

1. Set `revoked_at`
2. Kill sessions subject → object (target ≤60s in S5 done criteria)
3. Optional `GrantRevoke` control message / gossip to object host replicas (not full guest identity flood)
4. Audit

---

## Wire deltas (protocol — S5 / C1b)

| Message | Change |
|---------|--------|
| `JoinAccept` | Unchanged crypto |
| `MembershipSnapshot` after guest accept | **Skip** or single-host only |
| `GrantAnnounce` / `GrantRevoke` | New control messages as needed; not full guest flood |
| `build_snapshot` | Exclude `mesh_role=guest` from member snapshots |

---

## Capabilities and Admin

- Default member grant remains **without** Admin (alpha.1 `Capability::all()` = terminal/files/desktop/tcp).
- Admin may appear on a Grant only when explicitly issued (rare for guests; do not issue Admin to guests by default product policy).
- See [MASTER-KEY.md](MASTER-KEY.md) Admin migration and [JOIN.md](JOIN.md).

---

## Independence

| Mode | Grants |
|------|--------|
| MyMesh only | CLI `grant create/list/revoke` without Carrier |
| Carrier + MyMesh | Preferred share/revoke UX; same store |

---

## See also

- [GUEST.md](GUEST.md) — guest onboarding and roster isolation
- [MASTER-KEY.md](MASTER-KEY.md) — who may issue grants
- [JOIN.md](JOIN.md) — member join still uses full snapshot
- [CARRIER-NEXT.md](CARRIER-NEXT.md) — S5 sequences and done criteria
- [PAIR-V2.md](PAIR-V2.md) — dual-scan may bind `guest=true` + `grant_id` (S5)
