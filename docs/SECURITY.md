# Security model (alpha)

**Audience:** operators running MyMesh v0.1.0-alpha.1  
**Status:** best-effort documentation; not a formal audit.

## Trust model

1. **Long-term identity** — each node has an Ed25519 keypair. Device id = public key bytes.
2. **Allowlist** — only devices in `devices.json` with `Trusted` may use terminal/files.
3. **Join gate** — unknown peers may only present a **JoinRequest** when the host is **armed** (`connect-request allow`). Otherwise connections from unknowns are dropped.
4. **Human approval** — host operator must `requests accept` (or deny). Arming auto-clears after accept and expires by timeout.
5. **Transport** — iroh provides encrypted QUIC paths; relays should not see plaintext app data (trust iroh’s design; MyMesh does not re-encrypt beyond session/protocol layering already in place).

## What linking proves

- Joiner proved possession of the private key matching the device id (signed JoinRequest).
- Host proved possession of its key on JoinAccept.
- Operator intent on the host (accept).

It does **not** prove the joiner machine is free of malware. A trusted peer with Terminal+Files can act as your user on the agent host.

## Privilege

| Component | Alpha.1 behavior |
|-----------|------------------|
| `mymesh serve` | Runs as the invoking OS user |
| Shell | PTY as that user |
| Files | Sandbox under configured root (default: home) |

There is **no** separate “remote user” mapping yet. Future system installs must not default to root (see [INSTALL-POLICY.md](INSTALL-POLICY.md)).

## Metadata / network

- Default path uses public iroh infrastructure for NAT traversal. Peers with internet can find each other by id; expect **some metadata leakage** to discovery/relay infrastructure (similar class to Syncthing global discovery / other P2P tools).
- Local/SPAKE mailbox modes reduce reliance on public pairing helpers but are not the default multi-machine path.

## Reporting issues

Prefer private disclosure for exploitable bugs until a security contact is formalized. For alpha, GitHub issues marked security are acceptable if no secret data is included.

## Not guaranteed in alpha

- Forward secrecy beyond what the transport provides
- Resistance to malicious trusted peers
- Stable threat model under system-wide install
- Formal verification or third-party audit
