# Pair control plane v2 — S0 contract

| Field | Value |
|-------|--------|
| **Status** | Normative contract freeze (S0) |
| **Slice** | S1–S2 implement; this doc freezes wire, confirm algorithm, fail-closed rules |
| **Source** | [CARRIER-NEXT.md](CARRIER-NEXT.md) §S0–S2, Wave A protocol appendix |
| **Related** | [DEMO-PAIR.md](DEMO-PAIR.md) (E2E demo), [JOIN.md](JOIN.md), [MASTER-KEY.md](MASTER-KEY.md), [GUEST.md](GUEST.md), [SECURITY.md](SECURITY.md), [THREATS.md](THREATS.md) (C1–C2) |

---

## Goals

- Internet-first **product** pair: dual-scan + iroh machine completion; LAN `host` **optional**
- Wave A zero-HTTP decide = **confirm-on-machine** (phone is not an iroh peer)
- Freeze v2 bootstrap, SessionDecision, confirm-code algorithm, error codes, deprecation of required `host`

**S1 alone does not claim “internet decide from phone.”** That exit is S2 (confirm-on-machine).

---

## Independence matrix (pair)

| Mode | Required? | Pair path |
|------|-----------|-----------|
| **MyMesh only** | Required | CLI `link` / `requests accept`; operator `pair confirm` when identities known OOB |
| **Carrier + MyMesh** | Preferred UX | Dual-scan + direct host **or** confirm codes |

“MyMesh-only dual-scan” is **not** a thing: dual-scan **scan UX** requires phone (or future camera on machine). Confirm-on-machine does **not** require the phone to stay online after codes are transcribed.

---

## Bootstrap URL

```text
# v1 (alpha.1, still accepted)
carrier://pair?v=1&host=<url>&token=<b64url>&fp=<fp>&mesh=<id>

# v2
carrier://pair?v=2&sid=<ulid>&did=<64hex>&token=<b64url>&nonce=<b64url-16B>&fp=<fp>
                 &ep=direct|confirm|relay
                 &host=<optional>
                 &mesh=<optional>
                 &relay=<optional>
                 &tlspin=<optional>   # S9 / D2 — SPKI pin when host is HTTPS
```

### Parse rules (normative)

| Version | `host` | `nonce` | Behavior |
|---------|--------|---------|----------|
| **v1** | **Required** | Absent | Current alpha.1 behavior |
| **v2** | **Optional** | **Required** (base64url of 16 raw bytes) | If host absent → mode `confirm` (or explicit `ep=confirm`) |

- Do **not** fail parse when host absent on v2.
- **Do** fail parse when v2 `nonce` missing or malformed (KD27).
- `relay` / `ep=relay`: **not Wave A** product path; self-host only if ever (KD31).
- `tlspin` is **optional**. When present: see [TLS pin (`tlspin`)](#tls-pin-tlspin) — pin requires `https://` host; clients **fail closed** on pin mismatch.

### TLS pin (`tlspin`)

Optional certificate pin for **direct** HTTPS pair hosts (S9 / PR D2). Release cleartext policy is **unchanged**: Carrier release already denies cleartext HTTP; MyMesh LAN lab may still emit `http://` host **without** a pin.

| Topic | Normative |
|-------|-----------|
| Wire | `tlspin=sha256/<base64>` query param on v2 QR |
| Digest | **SHA-256** over the DER-encoded **SubjectPublicKeyInfo (SPKI)** of the leaf (or pinned) certificate |
| Base64 | Standard Base64 **or** base64url; padding optional. Emitters SHOULD use **base64url no padding** (URL-safe) |
| Prefix | Canonical prefix is lowercase `sha256/`; parsers SHOULD accept `SHA256/` |
| Host | When `tlspin` is present, `host` **must** be `https://…`. Pin + cleartext / missing host → **fail closed** at emit and at client |
| Client | Before sending the bootstrap Bearer token on direct ep, verify peer SPKI against pin; **mismatch → abort** (do not send token) |
| Absent pin | No SPKI check; behaviour unchanged (TOFU `fp` still applies for host identity) |
| Lab HTTP | `http://` host without pin remains valid for debug / LAN alpha |

```text
# Example shape only (illustrative — not a valid 32-byte digest encoding)
tlspin=sha256/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde

# Android Network Security Config style also accepted on parse:
tlspin=sha256/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/abcde=
```

**CLI (resident):**

```bash
mymesh pair dual --host https://pair.example:8443 --tlspin 'sha256/<base64…>'
```

**MyMesh helpers:** `mymesh_core::{parse_tls_pin, verify_tls_pin, check_direct_host_tls_pin}` — Carrier D3 wires the verify hook into the pair HTTP client TLS stack.

### Deprecation of required `host`

| Topic | Policy |
|-------|--------|
| v1 QR `host` required | Accepted through Wave B+ compat window |
| v2 without `host` | `mymesh pair dual` after A3 (KD23) |
| `/pair/v1/*` | Until D5; then `--pair-v1` escape |
| After A3 | `pair dual` emits **v2**; `mymesh carrier` stays **v1** until D5, then v2 default with `--pair-v1` |

```text
T0     S0 docs
T0+A3  pair dual → v2; carrier → v1
T0+A5  confirm path product internet exit
T0+D5  carrier default v2
T+6mo  optional remove v1 (major)
```

---

## Wire types (S0 goldens)

```rust
pub struct PairBootstrapV2 {
    pub v: u32,                    // 2
    pub sid: String,               // ULID session
    pub did: String,               // host/resident device_id hex
    pub fp: String,
    pub mesh: Option<String>,
    pub token: String,             // arm-scoped bootstrap (32B b64url)
    pub nonce: String,             // REQUIRED: base64url of 16B session nonce
    pub host: Option<String>,      // OPTIONAL direct hint
    pub ep: PairEndpointClass,     // direct | confirm | relay
    pub relay: Option<String>,
    pub tlspin: Option<String>,    // OPTIONAL: sha256/<base64> SPKI pin (HTTPS host only)
}

pub enum PairEndpointClass {
    Direct,
    Confirm,  // Wave A default when no reachable host
    Relay,
}

pub struct SessionDecision {
    pub sid: String,
    pub decision: PairDecision, // accept | deny
    pub joiner_device_id_hex: String,
    pub resident_device_id_hex: String,
    pub ts: String, // RFC3339
    pub nonce: String, // from session; binds decide
    pub person_id: Option<String>,
    pub sig_hex: Option<String>, // optional person sig Wave A (audit only)
}
```

### Nonce (normative)

- **16 raw bytes** per session.
- Wire as **base64url no padding** in QR (`nonce=`), `GET /pair/v2/status`, and `SessionDecision.nonce`.
- HMAC material uses the **raw 16 bytes** (not the ASCII base64url string).
- Same bytes in PairSession file, QR_A, status echo, and SessionDecision.
- Status may echo nonce for direct-path clients; must match QR. Phone must **not** call status solely to learn nonce — QR is the offline channel.

---

## PairSessionStore

```text
# paths.data_dir/pair-sessions/<sid>.json  mode 0600
PairSessionFile {
  sid, mesh_id,
  resident_device_id,   // did from QR / host
  token_hash,           // SHA-256 of raw token (store hash only on disk)
  nonce: [u8; 16],      // REQUIRED; same bytes as QR_A + status + SessionDecision
  until: DateTime,
  joiner_device_id: Option,
  joiner_label: Option,
  joiner_fp: Option,
  phase: PairPhase,
  decision: Option<JoinDecision>,
  confirm_consumed: bool,
  ep: PairEndpointClass,
  tls_pin: Option,      // optional wire form sha256/… when QR advertises tlspin
  created_at, updated_at
}

PairPhase =
  armed | bound | decided | completing | completed | failed_partial | expired
```

- Store under agent **`Paths`**. `mymesh serve` is source of truth.
- `mymesh carrier` is an optional HTTP facade on the same disk state.
- Wave A also adds agent-integrated `mymesh pair *` CLI so headless decide works **without** the carrier process.

### Handoff state machine (summary)

| Phase | Entry | Exit success | Fail closed notes |
|-------|-------|--------------|-------------------|
| `armed` | `pair dual` / arm | joiner bound | Confirm with 0 pending → **`not_bound`** (stay armed; **do not hang**) |
| `bound` | joiner_did set | decide accept/deny | expire / wrong peer |
| `decided` | confirm or POST decide | join loop consumes | — |
| `completing` | Accept taken by host loop | JoinAccept + local Trusted | iroh fail → `failed_partial` |
| `completed` | both sides Trusted (member) or bilateral guest trust | — | — |
| `failed_partial` | one-sided trust | retry | timeout |
| `expired` | until < now | — | new session |

---

## Endpoints

```text
GET  /pair/v2/status          # public: sid, ep, mesh, fp, armed, protocol_version=2, nonce
GET  /pair/v2/pending         # Bearer; pending joins bound to this sid only
POST /pair/v2/decide          # Bearer + SessionDecision; verifies joiner bound
POST /pair/v2/session/bind    # machine-local or Bearer: bind joiner did to sid
```

v1 endpoints remain (compat) until deprecation policy above.

### Pair / mesh error codes (S0 freeze)

```text
// Mesh API
MeshErrorCode = Unauthorized | Forbidden | NotFound | BadRequest
              | Conflict | RateLimited | Internal

// Pair v2: reuse PairErrorCode + SessionNotBound | SessionPhase
// Operator/CLI confirm: not_bound | ambiguous_session | already_decided
//   | session_gone | ambiguous_pending | bad_code
```

---

## Confirm-code algorithm (frozen S0; implement S2)

```text
pepper = bootstrap_token_raw (32B)  // arm-scoped; never leave machine except QR token to phone
material_accept = "mymesh-pair-confirm-v1" || 0x01 || sid || joiner_did || resident_did || nonce
material_deny   = "mymesh-pair-confirm-v1" || 0x00 || sid || joiner_did || resident_did || nonce
code_accept = base32(truncate(HMAC-SHA256(pepper, material_accept), 5 bytes))  // ~8 chars
code_deny   = base32(truncate(HMAC-SHA256(pepper, material_deny), 5 bytes))
```

| Rule | Normative |
|------|-----------|
| Phone computes codes | **Locally** after dual-scan bind using **token + nonce from QR_A** (no HTTP on `ep=confirm`) |
| Encoding | **Crockford base32** |
| **Display** | **4-4 groups** (e.g. `ABCD-EFGH`) (KD29) |
| Input | **Ignore hyphens** |
| Single-use | On success set `confirm_consumed=true` |
| Binding | Codes bind **exact** `joiner_did`; cannot accept a different pending peer |
| Machine verify | Same formula; constant-time compare |

---

## Confirm CLI — fail-closed (normative Wave A)

```bash
mymesh pair dual
mymesh pair dual --join --resident <id>
mymesh pair status [--sid]
mymesh pair confirm <code>   # verifies HMAC; single-use
mymesh pair retry <sid>
```

### `mymesh pair confirm <code> [--sid <sid>] [--joiner <did>]`

1. Resolve session: `--sid` or unique active non-expired session; if ambiguous → `ambiguous_session`.
2. If `confirm_consumed` or phase in `{decided, completing, completed, expired, failed_partial}` → `already_decided` / `session_gone` (idempotent ok only if same decision already applied).
3. **Binding gate (normative):**
   - If `phase == bound` and `joiner_device_id` is Some → use that joiner for HMAC material.
   - Else if `phase == armed` and **exactly one** JoinStore pending under this arm → **bind** that pending (phase→bound), then verify.
   - Else if `phase == armed` and **zero** pending → **fail closed** immediately: exit code **`not_bound`**, message: “Joiner has not dialed yet — wait for JoinRequest / finish dual-scan order, then re-run confirm.” **Do not hang.**
   - Else if multiple pending and not bound → `ambiguous_pending` (require `--joiner <did>` only if recomputed code matches that did + session nonce/token; then bind).
4. Recompute code_accept and code_deny for bound joiner; constant-time compare to input.
5. On match: `write_decision` to JoinStore for **that** joiner_did only; phase=`decided`; `confirm_consumed=true`; disarm rules as alpha.1 on accept.
6. On mismatch: `bad_code` (rate-limited); do not bind randomly.

Phone UX: if user confirms too early, operator sees `not_bound` and retries after B dials — codes remain valid until arm TTL / consume.

---

## SessionDecision verification (HTTP path)

```text
POST /pair/v2/decide
Authorization: Bearer <token>
{ SessionDecision }
```

1. Bearer token ct_eq current arm token.
2. `sid` matches open session.
3. `joiner_device_id_hex` == session.joiner_device_id (must be bound).
4. `resident_device_id_hex` == session.resident_device_id.
5. `nonce` matches session.nonce (anti-replay across sessions).
6. `ts` within skew ±5 min.
7. Idempotent: if phase already `decided|completing|completed` with same decision+joiner → ok; if different decision → conflict.
8. Optional person `sig_hex` over canonical SessionDecision bytes — audit only in Wave A.
9. If armed + single pending: bind first (same as confirm); if zero pending: **409 `not_bound`**.

---

## Dual-scan ceremony (product path)

```text
1. Machine A (resident): mymesh pair dual [--host https://… --tlspin sha256/…]
   → PairSession sid; QR_A v2 (sid, did_A, fp_A, token, nonce, mesh, ep, host?, tlspin?)
2. Machine B (joiner): mymesh pair dual --join --resident <did_A|words>
   → iroh join toward A; QR_B (did_B, fp_B, label) for phone
3. Phone: Scan A → SessionDraft; Scan B → bind joiner; show both fps → L2 Accept/Deny
4a. If host reachable: POST /pair/v2/decide with SessionDecision
4b. Else: show code_accept / code_deny; user: mymesh pair confirm <code> on A
5. A writes JoinStore decision for bound joiner only; phase decided → completing
6. Existing join loop take_decision → JoinAccept; B Trusted on A
7. B applies host trust; member path sends membership snapshot (guest path: see GUEST.md)
8. phase completed; audit on phone if used
```

### Wave A decide priority (Carrier after dual-scan bound)

```text
1. If host hint present → try POST /pair/v2/decide (2s timeout)
2. Else → show confirm codes; user runs mymesh pair confirm <code>
3. Relay — not in Wave A
```

### Artifacts

| Artifact | Producer | Contents |
|----------|----------|----------|
| QR_A | Resident `pair dual` | v2 with **required nonce** |
| QR_B | Joiner | `mymesh://pair-peer?v=1&did&fp&label` (phone-only; not pair HTTP bootstrap) |
| Confirm code | Phone local HMAC | Algorithm above |
| JoinAccept / MembershipSnapshot | Existing | Member path full snapshot; **guest skips full roster** ([GUEST.md](GUEST.md)) |

---

## Join integration

In `handle_join_as_host`:

1. When PairSession exists in `armed|bound` and pending joiner arrives, **bind** `joiner_device_id` if not set (or verify match).
2. `take_decision`: if session present, only accept decision for **bound** joiner_did; ignore/reject other device ids.
3. Carrier HTTP and `mymesh pair confirm` both write JoinStore decision **and** session phase `decided`.

JoinStore remains source of truth for accept/deny outcomes ([JOIN.md](JOIN.md)).

---

## Control plane classes

| Class | Wave | Phone decide transport | Notes |
|-------|------|------------------------|-------|
| **A. Direct** | A+ | HTTP(S) to optional `host` | alpha.1 path; LAN optimization |
| **B. Confirm** | **A primary zero-HTTP** | No phone network to host | Confirm codes on machine TUI/CLI; machines finish over iroh |
| **C. Relay** | Optional later, self-host only | HTTPS to operator-run relay | **Not** Waves A–C product |

Device-to-device trust completion always uses **existing iroh dial-by-device-id**. Phone is never required to open TCP to a private LAN IP.

---

## Explicit non-placeholders

- Do not advertise “Internet pair complete” in UI until confirm path works (S2).
- Do not log tokens or raw pepper.
- Handoff must use JoinStore + DeviceStore upsert — not UI-only “linked” on phone.
- Phone does not deliver decide via iroh pair mailbox.

---

## Done criteria (S1 / S2 — frozen intent)

### S1

- [ ] v2 QR without `host` parses; does not crash
- [ ] v1 QR still works on LAN
- [ ] PairSessionStore persists; QR_A and status carry same nonce; parse fails if v2 missing nonce
- [ ] JoinStore bind: decision for wrong device id does not accept wrong peer
- [ ] **Not** required: phone-on-cellular completes decide without confirm (that is S2)

### S2

- [ ] Two real agents complete Trusted after dual-scan + confirm **without** phone HTTP to host
- [ ] Dual-scan + direct host still works on LAN
- [ ] Deny leaves joiner not Trusted
- [ ] Wrong confirm code for different joiner fails; cannot accept unbound peer
- [ ] Replay of old SessionDecision (wrong nonce/sid) fails
- [ ] Confirm with zero pending returns **`not_bound`** (fail closed, no hang); succeeds after single pending bind
- [ ] QR_A without nonce rejected by Carrier parse (v2)
- [ ] CLI link without phone still works
- [ ] Confirm-on-machine works operator-only if fps compared OOB

---

## See also

- [DEMO-PAIR.md](DEMO-PAIR.md) — dual-scan+confirm demo steps, harness, mock-pair-host lab-only
- [JOIN.md](JOIN.md) — CLI link, membership snapshot, migration from pair/v1
- [GUEST.md](GUEST.md) — guest accept skips full roster
- [MASTER-KEY.md](MASTER-KEY.md) — orthogonal in Wave A; dual authority later
- [GRANTS.md](GRANTS.md) — guest grants bound to pair session in S5
- [SECURITY.md](SECURITY.md) — trust and arming
- [CARRIER-NEXT.md](CARRIER-NEXT.md) — full sequences, threat model, PR plan
