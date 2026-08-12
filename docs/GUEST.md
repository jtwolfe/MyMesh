# Guest membership — S0 contract

| Field | Value |
|-------|--------|
| **Status** | Normative contract freeze (S0) |
| **Slice** | S5 implements protocol; this doc freezes membership rules |
| **Source** | [CARRIER-NEXT.md](CARRIER-NEXT.md) §S5, KD19 |
| **Related** | [GRANTS.md](GRANTS.md), [JOIN.md](JOIN.md), [MASTER-KEY.md](MASTER-KEY.md), [PAIR-V2.md](PAIR-V2.md), [SECURITY.md](SECURITY.md) |

---

## Role

A **guest** shares **one device** (the object host) without becoming a full mesh member. Guests get bilateral trust + a Grant; they must **never** learn the full mesh roster.

**KD19 / S0 freeze:** **Guests do not receive mesh-wide `MembershipSnapshot`.**

---

## Device mesh role

```text
MeshRole = member | guest
```

| Rule | Normative |
|------|-----------|
| Device roles | `member` \| `guest` only |
| Person owner | **Not** a `MeshRole`; lives in `mesh-owner.json` only (KD21) |
| Default for existing Trusted | Missing `mesh_role` → **Member** |
| Guest onboarding | Sets `mesh_role=guest` on bilateral DeviceRecords |

Migration: `devices.json` gains optional `mesh_role`; absent field = Member if Trusted. Capabilities unchanged (still no Admin unless granted).

---

## Guest onboarding protocol (normative)

**Not** the normal member join path (which calls `build_snapshot` of all trusted devices in `join.rs`).

```text
GuestInvite ceremony:
1. Owner/admin creates Grant
   (subject=guest_did or pending, object=host_did, role=guest, caps, not_after).
2. Guest pairs **only to object host** via:
   a) mymesh link <object-host-id> while host armed with --guest-grant <grant_id>
      OR
   b) dual-scan with session.flag guest=true and grant_id bound
3. On Accept for guest session:
   - Object host upserts DeviceRecord {
       mesh_role: guest,
       capabilities: grant.caps,
       trust: Trusted
     }
   - Send JoinAccept **without** full MembershipSnapshot
     (omit snapshot frame OR MembershipSnapshot with members=[host only] + role guest)
   - Guest upserts only the object host as Trusted bilateral
     (mesh_role guest on guest's store for host)
4. Guest MUST NOT be inserted into mesh-wide gossip roster as a full member.
5. mesh sync / build_snapshot:
   - Exclude mesh_role=guest from snapshots sent to members
   - Members do not need guest list by default; object host keeps guest in local DeviceStore
   - Optional: members learn guest ids only if policy allows (default **no**)
```

### Wire delta (explicit; land with S5 / PR C1b)

| Message | Change |
|---------|--------|
| `JoinAccept` | Unchanged crypto |
| `MembershipSnapshot` after guest accept | **Skip** or single-host only |
| `GrantAnnounce` / `GrantRevoke` | Gossip revoke to object host replicas if any; not full guest identity flood |
| `build_snapshot` | Exclude `mesh_role=guest` from member snapshots |

---

## Session enforcement

See [GRANTS.md](GRANTS.md):

```text
if peer.mesh_role == Guest:
  require active Grant covering this node as object with cap
  check not_after, facet constraints
```

- Guest may open sessions only to the **object host** under grant caps.
- Other devices deny guest sessions.
- Compromising a guest never yields MMK or person seed ([MASTER-KEY.md](MASTER-KEY.md)).
- Operator response when a guest device is compromised: [RECOVERY.md](RECOVERY.md) runbook **G** (revoke grant; optional unlink).

---

## Topology / API visibility

| Auth / client | Sees guests? |
|---------------|--------------|
| Member `device_member` topology | Full **member** roster; guests not listed by default |
| `person_owner` / `mrk_proof` | Full members + grants summary (may include guest grants without flooding guest as member) |
| Guest device session | **Self + object host only** |
| `pair_read` (Carrier post dual-scan) | Session-minimal; not full household |

**Product:** Guest token / guest session **cannot** pull full roster.

---

## Revoke

Primary tool for ending guest access is **grant revoke** (not kick):

| | Grant revoke | Kick |
|--|--------------|------|
| Guest | Primary | N/A (not full member) |
| Member | Rare | Primary |

Revoke: `revoked_at`; kill subject→object sessions (≤60s target); `GrantRevoke` notice; audit. See [GRANTS.md](GRANTS.md).

---

## CLI (target — S5)

```bash
mymesh grant create --to <guest> --on <device> --caps terminal,files --days 7
mymesh grant list
mymesh grant revoke <grant_id>
```

CLI-only path without Carrier is first-class ([independence matrix](CARRIER-NEXT.md)).

---

## Sequence (share + revoke)

```text
Owner → object host: grant create guest→H
Guest → H: join guest path
H: Trusted guest role; no full snapshot
H → Guest: JoinAccept only (no full roster)
Guest ↔ H: sessions under grant caps
Owner → H: grant revoke
H: kill sessions; revoked_at
```

---

## Done criteria (S5; frozen intent)

- [ ] Guest cannot list other mesh members via snapshot/gossip
- [ ] Guest caps enforced; other devices deny guest sessions
- [ ] Revoke kills access ≤60s
- [ ] CLI-only path without Carrier
- [ ] Protocol tests: guest accept does not call full `build_snapshot`

---

## Explicit non-goals

- Guest as mesh-wide member with filtered UI only (must be protocol isolation, not cosmetics)
- Device role `owner`
- Full federation / Service objects (grant shape allows later; not S5)

---

## See also

- [GRANTS.md](GRANTS.md) — Grant schema and `allows()`
- [JOIN.md](JOIN.md) — member join still sends full snapshot
- [MASTER-KEY.md](MASTER-KEY.md) — dual authority; guest never holds MMK
- [RECOVERY.md](RECOVERY.md) — compromised guest runbook
- [PAIR-V2.md](PAIR-V2.md) — dual-scan guest flag (S5)
- [SECURITY.md](SECURITY.md) · [THREATS.md](THREATS.md) — trust model + C4 residual
- [CARRIER-NEXT.md](CARRIER-NEXT.md) — S5 full design
