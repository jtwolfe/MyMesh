# Security model (alpha)

**Audience:** operators running MyMesh v0.1.0-alpha.x  
**Status:** best-effort documentation; not a formal audit.  
**Threat model & S9 controls:** **[THREATS.md](THREATS.md)** (C1–C7 checklist, implemented vs planned)  
**S0 contracts:** [MASTER-KEY.md](MASTER-KEY.md), [GRANTS.md](GRANTS.md), [GUEST.md](GUEST.md), [PAIR-V2.md](PAIR-V2.md), [CARRIER-NEXT.md](CARRIER-NEXT.md)

## Trust model

1. **Long-term identity** — each node has an Ed25519 keypair. Device id = public key bytes.
2. **Allowlist** — only devices in `devices.json` with `Trusted` may use terminal/files (member path).
3. **Join gate** — unknown peers may only present a **JoinRequest** when the host is **armed** (`connect-request allow`). Otherwise connections from unknowns are dropped.
4. **Human approval** — host operator must `requests accept` (or deny), or pair decide / confirm-on-machine. Arming auto-clears after accept and expires by timeout.
5. **Transport** — iroh provides encrypted QUIC paths; relays should not see plaintext app data (trust iroh’s design; MyMesh does not re-encrypt beyond session/protocol layering already in place).

### Dual authority (S0 freeze; S3–S4 implement)

| Authority | Role |
|-----------|------|
| **Mesh master key (MMK / MRK)** | **Root of mesh policy** for mesh-destructive ops |
| **Carrier person owner claim** | Portable person binding; subordinate to MMK for destructive ops |
| **Host-local CLI** | Filesystem access to agent `Paths` = node admin on that machine |
| **Remote Admin cap** | Explicit grant only; **not** in default member capabilities |

Default member grant remains **without** Admin (`terminal` / `files` / `desktop` / `tcp`). See [MASTER-KEY.md](MASTER-KEY.md).

### Member vs guest (S0 freeze; S5 implement)

- Device `mesh_role` is `member` | `guest` only — never `owner` on a device.
- **Guests do not receive mesh-wide membership snapshots** ([GUEST.md](GUEST.md)).
- Guest access is Grant-scoped to one object host ([GRANTS.md](GRANTS.md)).

### Pair control plane

- **v1:** LAN `host` required in QR; phone HTTP decide ([JOIN.md](JOIN.md)).
- **v2:** optional host; **required session nonce**; confirm codes as Crockford base32 **4-4**; unbound confirm fails **`not_bound`** closed (no hang). See [PAIR-V2.md](PAIR-V2.md).

## S9 control checklist (summary)

Full detail, threat narratives, and honest status: **[THREATS.md](THREATS.md)**. Source design: [CARRIER-NEXT.md](CARRIER-NEXT.md) §S9.

| ID | Threat | Control | Status (this tree) |
|----|--------|---------|---------------------|
| **C1** | Session fixation | token + sid + nonce + TTL | **Implemented** (pair v2) |
| **C2** | Wrong joiner accept | bind joiner_did + confirm HMAC | **Implemented** |
| **C3** | Backup theft | password Argon2id AEAD | **Implemented** (owner sealed backup; MMK wrap separate) |
| **C4** | Guest residual | wipe + grant revoke | **Partial** — revoke done; continuity wipe planned (S8) |
| **C5** | Topology MITM | mesh-auth session; optional sig | **Partial** — mesh session enforced; `snapshot_sig` not yet |
| **C6** | Facet bleed | allowlists enforced S7 | **Planned** (schema only today) |
| **C7** | Decide brute force | rate limits | **Planned** (PR D1) |

Do **not** claim full S9 hardening until D1–D3 land and C4 residual wipe (Wave E) is real.

## What linking proves

- Joiner proved possession of the private key matching the device id (signed JoinRequest).
- Host proved possession of its key on JoinAccept.
- Operator intent on the host (accept / pair decide / confirm).

It does **not** prove the joiner machine is free of malware. A trusted peer with Terminal+Files can act as your user on the agent host.

## Privilege

| Component | Alpha behavior |
|-----------|----------------|
| `mymesh serve` | Runs as the invoking OS user |
| Shell | PTY as that user |
| Files | Sandbox under configured root (default: home) |

There is **no** separate “remote user” mapping yet. Future system installs must not default to root (see [INSTALL-POLICY.md](INSTALL-POLICY.md)).

## Metadata / network

- Default path uses public iroh infrastructure for NAT traversal. Peers with internet can find each other by id; expect **some metadata leakage** to discovery/relay infrastructure (similar class to Syncthing global discovery / other P2P tools).
- Local/SPAKE mailbox modes reduce reliance on public pairing helpers but are not the default multi-machine path.
- Pair HTTP (carrier) is LAN-oriented for v1; v2 confirm path does not require phone → private LAN IP.

## Reporting issues

Prefer private disclosure for exploitable bugs until a security contact is formalized. For alpha, GitHub issues marked security are acceptable if no secret data is included.

## Not guaranteed in alpha

- Forward secrecy beyond what the transport provides
- Resistance to malicious trusted peers
- Stable threat model under system-wide install
- Formal verification or third-party audit
- Online rate limits for pair decide / backup unwrap (**C7** — planned)
- Multi-identity facet isolation (**C6** — planned S7)
- Continuity wipe-on-leave for guest residual data (**C4** complete path — planned S8)

## Magic plane & SSH (alpha.3)

- **TCP tunnels** (SSH, expose, SOCKS, auto-ports) allow a trusted peer to reach **localhost ports** on the agent host as the agent user.
- Treat linked devices like accounts that can open `sshd` and any bound service on loopback.
- **Carrier** listens on a LAN-reachable HTTP port only while you run `mymesh carrier`; use firewall helpers explicitly.
- **SOCKS** is bound to loopback by default — do not rebind to `0.0.0.0` without understanding exposure.
- System DNS is **not** rewritten by MyMesh; that limits surprise traffic hijack.

## See also

- **[THREATS.md](THREATS.md)** — threat catalog + C1–C7 implemented vs planned  
- [MASTER-KEY.md](MASTER-KEY.md) · [GRANTS.md](GRANTS.md) · [GUEST.md](GUEST.md) · [PAIR-V2.md](PAIR-V2.md)  
- [JOIN.md](JOIN.md) · [CARRIER-NEXT.md](CARRIER-NEXT.md) · [ARCHITECTURE.md](ARCHITECTURE.md)
