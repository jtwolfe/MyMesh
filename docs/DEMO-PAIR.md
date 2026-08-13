# Pair E2E demo (Wave A — dual-scan + confirm)

**Status:** Product demo for **pair/v2** dual-scan + confirm-on-machine (Wave A exit).  
**Contract:** [PAIR-V2.md](PAIR-V2.md) (normative) · [JOIN.md](JOIN.md) · [CARRIER-NEXT.md](CARRIER-NEXT.md)  
**Usage:** [USAGE.md](USAGE.md) · day-to-day CLI  
**Carrier twin:** Carrier repo `docs/DEMO-PAIR.md` (phone APK, mock host, Android checklist)

| Path | Role | When to use |
|------|------|-------------|
| **A — dual-scan + confirm** | **Primary product demo** | Two machines + phone; phone **need not** reach host HTTP |
| **B — dual-scan + direct host** | Advanced LAN helper | Optional `--host` in QR_A as a **private last-mile hint**; HTTP decide only if Carrier Advanced “LAN helper / HTTP decide” is on |
| **C — carrier single-host LAN** | Migration / LAN helper | Default **v2** after D5; `--pair-v1` for alpha.1 |
| **Lab — mock-pair-host** | **Lab only** | Lives in **Carrier** repo; emulator / unit fixtures — **not** product |

**Honesty (KD14):** `mock-pair-host` (Carrier `tools/mock-pair-host`) implements **pair/v1** fixtures for unit/ceremony tests and emulator loops. It is **not** a substitute for dual-scan + iroh completion. Do not present mock accept as “internet-first pair.” This MyMesh tree does **not** ship mock-pair-host.

---

## What works where

| Setup | Dual-scan (QR_A + QR_B) | Decide | Machines become Trusted |
|-------|-------------------------|--------|-------------------------|
| **MyMesh only** (no phone) | No scan UX | CLI `link` + `requests accept`, or operator `pair confirm` if codes known OOB | Yes (CLI path) |
| **Two machines + Carrier phone, no phone→host HTTP** | Yes | Confirm codes → `mymesh pair confirm <code>` on resident | Yes — **Wave A product exit** |
| **Two machines + phone on LAN with reachable host** | Yes | Default: confirm codes + enroll-via-hint. `POST /pair/v2/decide` only with Advanced LAN helper | Yes (Path A; Path B if helper on) |
| **Phone + mock-pair-host only** | No | v1 mock Accept | **No** real mesh trust — lab UI only |
| **CI / no Android** | Harness stands in for phone codes | `apply_pair_confirm` in-process | Yes — [two_agent_harness](../crates/mymesh-session/src/two_agent_harness.rs) (PR A7) |

Phone is **never** an iroh peer. Machines complete trust over existing iroh join. Dual-scan **scan UX** requires a camera (or paste); confirm-on-machine does **not** require the phone to stay online after codes are transcribed.

---

## CLI surface (implemented)

```text
mymesh pair dual [--host <url>] [--ttl N]              # resident: arm + PairSession + QR_A v2
mymesh pair dual --join --resident <id|words>          # joiner: QR_B + dial join
mymesh pair confirm <code> [--sid <sid>] [--joiner <did>]  # HMAC verify → JoinStore
mymesh pair status [--sid <sid>]
mymesh pair retry [sid]                                # expire + re-arm dual (confirm ep)
```

| Command | Role |
|---------|------|
| `pair dual` | Arms join window + mints PairSession; prints **QR_A** (`carrier://pair?v=2&…&nonce=…`). Without `--host` → `ep=confirm` (Wave A zero-HTTP). With `--host http://ip:port` → `ep=direct`. |
| `pair dual --join --resident X` | Prints **QR_B** (`mymesh://pair-peer?v=1&did&fp&label`) and dials resident join over iroh. |
| `pair confirm <code>` | Verifies Crockford base32 **4-4** HMAC (hyphens optional); single-use; fail-closed `not_bound` if joiner has not dialed. |
| `pair status` | Active session phase, ep, joiner bind, pending joins. |
| `pair retry` | Expire previous session; arm a fresh dual (confirm path). |

Host process: **`mymesh serve`** owns iroh **and** `/pair/v2` + `/mesh/v1` on **:17878**. **Path A** decide (`mymesh pair confirm`) is the product Accept path. `host=` in QR_A (TUI / `start_carrier` / optional `pair dual --host`) is a **private last-mile hint** — never product copy; do not strip it. **Path B** HTTP decide is Carrier Advanced LAN helper against **serve-owned** `/pair/v2`. Standalone `mymesh carrier` is **lab-only** (refuses bind when serve is up).

---

## Ceremony overview (product)

```text
1. Machine A (resident): mymesh serve  +  mymesh pair dual
   → QR_A: carrier://pair?v=2&sid&did&token&nonce&fp&ep=confirm|direct&host?&mesh?
2. Machine B (joiner):   mymesh pair dual --join --resident <did_A|words>
   → dials A over iroh; prints QR_B: mymesh://pair-peer?v=1&did&fp&label
3. Phone (Carrier debug APK):
   Scan QR_A → draft; Scan QR_B → bind; review both fingerprints → L2 Accept/Deny
4a. Default Accept: confirm codes (Crockford 4-4) + enroll-via-hint
     (POST /mesh/v1/enrollments using the private host= hint when reachable).
     Operator: mymesh pair confirm <code>  on A
4b. Advanced LAN helper / “use HTTP decide”:
     POST /pair/v2/decide  SessionDecision  (Bearer token; ≈2s timeout)
     Dial on joiner only if LAN helper is on and QR_B had host+token.
5. A writes JoinStore decision for bound joiner only → join loop JoinAccept
6. Both DeviceStores Trusted (member path); phone audit with both fps
```

**Decide priority on Carrier after dual-scan bind** ([PAIR-V2.md](PAIR-V2.md)):

1. **Default:** confirm codes + enroll-via-hint (`POST /enrollments` via cached `host=` hint).  
2. **Advanced LAN helper / HTTP decide:** try `POST /pair/v2/decide` (~2s); fallback to confirm.  
3. Relay — not Wave A.

`host=` is never rendered. Serve owns HTTP; the hint is not product copy.

---

## Path A — dual-scan + confirm (primary)

**Exit:** Two real agents become **Trusted** after dual-scan + confirm **without** phone HTTP to host.  
Harness gate (no Android): `two_agent_harness` below. Phone UX: Carrier `docs/DEMO-PAIR.md`.

### Prerequisites

1. MyMesh built with Wave A pair CLI (`pair dual` / `confirm` / JoinStore bind).  
2. Two machines (or two `MYMESH_HOME` dirs) that can complete iroh join.  
3. For full product UX: Carrier debug APK with dual-scan. Phone network to host is **not** required for this path.  
4. `mymesh serve` (or systemd user unit) running on the resident.

### Steps

```bash
# --- Machine A (resident) ---
mymesh serve &
# optional firewall only if you also exercise direct host HTTP (Path B):
# mymesh firewall ufw allow   # TCP 17878
mymesh pair dual
# prints QR_A (v2, required nonce, ep=confirm). Leave session armed.

# --- Machine B (joiner) ---
mymesh pair dual --join --resident <did_or_words_from_A>
# dials A; prints QR_B (mymesh://pair-peer?…)

# --- Phone (Carrier debug APK) ---
# Unlock → Pair mesh join
# 1) Scan / paste QR_A (carrier://pair?v=2&…)
# 2) Scan / paste QR_B (mymesh://pair-peer?…)
# 3) Review both fingerprints (resident + joiner)
# 4) L2 Accept (or Deny)
#    → app shows confirm codes (accept + deny, 4-4) when host absent/unreachable

# --- Machine A (operator) ---
mymesh pair confirm <CODE>    # e.g. ZCRE-1R14; hyphens optional
mymesh pair status            # optional
# on partial handoff: mymesh pair retry [sid]
```

### Exit checks

- [ ] A: `mymesh serve` + `mymesh pair dual` emits **v2** QR with **nonce**  
- [ ] B: `mymesh pair dual --join --resident <id>` dials A and shows QR_B  
- [ ] Phone: dual-scan binds joiner; UI shows **both** fingerprints  
- [ ] L2 Accept → confirm codes when no reachable host  
- [ ] `mymesh pair confirm <accept-code>` → both sides **Trusted** (no CLI `requests accept`)  
- [ ] Deny code → joiner **not** Trusted  
- [ ] Confirm with zero pending → **`not_bound`** (fail closed, no hang); retry after B dials  
- [ ] Wrong code / wrong joiner → reject; cannot accept unbound peer  

### Operator-only (no phone)

Compare fingerprints out-of-band, then use classic CLI:

```bash
# Host
mymesh connect-request allow
mymesh id

# Joiner
mymesh link '<hex-or-words-or-uri>'

# Host
mymesh requests accept <id-prefix>
```

Confirm-on-machine without Carrier is only practical if codes are computed by a trusted tool with the same HMAC inputs (token, nonce, sid, dids) — not a casual path. Dual-scan **scan UX** requires a camera.

---

## Path B — dual-scan + direct host (Advanced LAN helper)

Same as Path A through dual-scan bind. QR_A may include `host=` (`ep=direct`) as a **private last-mile hint** — TUI / `start_carrier` still emit it (do not strip).  
`/pair/v2/decide` is served by **`mymesh serve`** on `:17878`. `pair dual --host` only puts the hint in QR_A. Carrier **does not** POST decide unless Advanced “LAN helper / HTTP decide” is on. If serve is down, lab `mymesh carrier` may bind; if serve is up, `mymesh carrier` refuses (`serve owns pair HTTP`). Without the helper (or if HTTP fails), the phone uses confirm codes + enroll-via-hint (Path A).

```bash
# --- Machine A (resident) ---
mymesh serve &                     # iroh + pair/v2 + mesh/v1 on :17878
mymesh firewall ufw allow          # TCP 17878 for phone LAN HTTP (explicit only)
# mymesh carrier                   # lab-only if serve is down; refuses when serve owns :17878
mymesh pair dual --host http://<lan-ip>:17878
# QR_A: ep=direct + host hint. Leave session armed.

# --- Machine B (joiner) ---
mymesh pair dual --join --resident <did_or_words_from_A>

# --- Phone ---
# Dual-scan as Path A. Default Accept: confirm codes + enroll-via-hint.
# Enable Advanced “LAN helper / HTTP decide” to POST /pair/v2/decide (~2s).
# On helper success: no confirm codes required.
# On failure / timeout / helper off: confirm codes (Path A).
```

### Exit checks

- [ ] With Advanced LAN helper on, phone on same LAN can Accept via `/pair/v2/decide` without typing codes  
- [ ] Helper off: Accept shows confirm codes even if `host=` is in the QR  
- [ ] Unreachable host does **not** fail open: UI stays on confirm codes  
- [ ] SessionDecision binds `sid`, `nonce`, resident + joiner dids ([PAIR-V2.md](PAIR-V2.md))  
- [ ] TUI does **not** show the LAN URL; QR payload still has `host=`

---

## Path C — carrier single-host LAN (lab; `--pair-v1` escape)

Lab helper when **serve is down**. After F4p, product path is `mymesh serve` + TUI MMA1 arm. Default QR is **pair/v2**; `--pair-v1` restores alpha.1. **Not** the Wave A dual-scan product exit. `mymesh carrier` **refuses** if serve already owns `:17878`.

```bash
# --- Host A ---
mymesh serve &                     # owns /pair/v2 on :17878; TUI arms QR via MMA1
mymesh firewall ufw allow          # or firewalld / ufw 17878/tcp
# mymesh carrier                   # lab-only if serve is down
# mymesh carrier --pair-v1         # escape: alpha.1 carrier://pair?v=1&… LAN QR

# --- Joiner B ---
mymesh link '<host-hex-or-words-or-uri>'

# --- Phone ---
# Unlock → Pair mesh join → paste/open QR (v2 default; v1 if --pair-v1)
# Wait for pending → verify words → Accept (L2)
```

| Note | Detail |
|------|--------|
| Default QR from TUI / MMA1 (or lab `mymesh carrier`) | **v2** (`ep=direct` + LAN `host`; PairSession armed). Escape: `--pair-v1` |
| `mymesh pair dual` | Emits **v2** (post A3) |
| Port | **17878** |

---

## Two-agent harness (PR A7 — CI, no Android)

In-process gate for Path A without phone or real iroh endpoints. Uses `LocalFabric` + the same `apply_pair_confirm` / JoinStore path as the CLI.

**Source:** [`crates/mymesh-session/src/two_agent_harness.rs`](../crates/mymesh-session/src/two_agent_harness.rs)

```text
1. Resident A: arm join window + PairSessionStore::arm_new  (pair dual)
2. Agent A accepts on LocalFabric
3. Joiner B dials + run_join_as_guest                     (pair dual --join)
4. Test helper computes accept code (phone-local HMAC stand-in)
5. apply_pair_confirm on A                                (pair confirm)
6. Host join loop take_decision → JoinAccept + membership
7. Both DeviceStores TrustState::Trusted
```

```bash
# From MyMesh workspace root
cargo test -p mymesh-session --lib two_agent
```

Coverage includes accept (both Trusted), deny (not Trusted), and direct `handle_join` + confirm. This is the **merge gate** for confirm-on-machine without an Android device.

---

## Lab — mock-pair-host (Carrier only, not product)

**Does not live in this repository.** Carrier `tools/mock-pair-host` + `scripts/demo-pair.sh` exercise **pair/v1** QR → TOFU → pending → L2 decide → audit on a single machine / emulator.

| Fact | Detail |
|------|--------|
| Repo | **Carrier** (not MyMesh) |
| Purpose | Phone UI / client unit tests |
| Port (default) | **18787** (avoids MyMesh **17878**) |
| Dual-scan / QR_B / confirm codes | **No** |
| iroh / real DeviceStore mutual trust | **No** |

Do not demo mock Accept as the Wave A internet-first pair. For product demos use Path A or B with real `mymesh pair dual`. Full lab steps: Carrier `docs/DEMO-PAIR.md`.

---

## Artifacts

| Artifact | Producer | Contents |
|----------|----------|----------|
| QR_A | Resident `mymesh pair dual` | v2 with **required nonce**; `ep=confirm` or `direct` |
| QR_B | Joiner `pair dual --join --resident <id>` | `mymesh://pair-peer?v=1&did&fp&label` (phone-only) |
| Confirm code | Phone local HMAC (or harness helper) | Crockford base32, display **4-4** |
| JoinAccept / membership | Existing join loop | Member path full snapshot; guest: [GUEST.md](GUEST.md) |

Confirm algorithm (normative): [PAIR-V2.md](PAIR-V2.md) — pepper = bootstrap token; material binds `sid`, joiner did, resident did, nonce.

---

## Rollback

- `mymesh requests accept` / `deny` remain available on the host.  
- `mymesh pair retry [sid]` expires a stale session and arms a fresh dual.  
- Stop `mymesh serve` (pair HTTP lives with the agent). Lab `mymesh carrier` only if serve was down.  
- Lab only: stop mock-pair-host in the Carrier tree.

---

## Related

- [PAIR-V2.md](PAIR-V2.md) — v2 wire, confirm HMAC, fail-closed confirm, dual-scan ceremony  
- [JOIN.md](JOIN.md) — CLI link, membership snapshot, v1/v2 migration  
- [USAGE.md](USAGE.md) — day-to-day linking and carrier  
- [SECURITY.md](SECURITY.md) — trust and arming  
- [RECOVERY.md](RECOVERY.md) — re-pair after nuclear recovery (R3); dual-authority runbooks  
- [CARRIER-NEXT.md](CARRIER-NEXT.md) — Wave A–E plan, KD14 lab honesty  
- [GUEST.md](GUEST.md) — guest accept skips full roster  
- Carrier repo: `docs/DEMO-PAIR.md`, `tools/mock-pair-host`  
