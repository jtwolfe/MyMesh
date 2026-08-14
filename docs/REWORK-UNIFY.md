# Rework: unify carrier + MyMesh

## Goal

Strip MyMesh back to a simple device mesh, and make carrier a simple person-app that owns devices on the same continuous iroh P2P network. First win: from the phone, use your stuff without thinking about IPs.

## Keep

- 24-word device-to-device pairing (the simple mesh with no phone)
- iroh/QUIC fabric, dial proxy, agent, names, SSH/SOCKS/expose as node features
- Existing iroh relays for first contact / punch-fail fallback
- alpha.3 machine behavior as the good snapshot (tag v0.1.0-alpha.3 stays frozen)

## Kill (this repo)

- Carrier HTML/QR "scanner only" page
- pair/v1 HTTP, pair/v2, /mesh/v1 control plane
- Any "phone is not a mesh node" assumption
- Do not grow social/storage UI in MyMesh

## Identity

- A MyMesh node has a device identity (24-word).
- A person lives in carrier (one user identity, keys in the vault).
- The person OWNS devices. Devices can still pair to each other with 24-word when no phone is present.
- The phone is both the person vault AND an iroh peer on the same fabric.

## Own-device ceremony (only this)

1. Carrier: Add device
2. Scan the node's QR
3. Type a short one-time challenge on the node
4. Carrier owns that device

A photo of a QR is not enough. No LAN HTTP enroll dance.

## Mesh

- Carrier can create a mesh and add/remove/update devices.
- Remove = person no longer owns the node; node forgets that owner.
- After enroll, carrier and owned nodes are the same P2P mesh.

## Network

- Stick with iroh. Not Tor. Iroh is n0's P2P stack (QUIC, hole punching, relays), not Tor.
- Bootstrap via existing iroh relays. After handshake, P2P. Relay only if punch fails.
- Do not build a MyMesh-operated public relay.

## Security

- Owner keys never live in MyMesh plaintext.
- Challenge-on-node for enroll.
- 24-word remains the device pairing/recovery secret.
- No leftover pair/v1 ports after the strip.

## Out of scope on this branch

Glass, holofs, FamilyFleet, Wave F admin, crates.io, Tor.

## Work order (MyMesh share)

1. This DESIGN note
2. Strip carrier-specific pairing from MyMesh; leave 24-word join + agent
3. Accept phone as an iroh peer / owned device
4. Node side of own-device: show QR + accept short challenge
5. Honor owner add/remove/update from carrier over the mesh
6. CI: enable GitHub Actions to build mymesh linux binaries from this branch and from tags (existing ci.yml is disabled; turn it on, do not invent crates.io publish)
