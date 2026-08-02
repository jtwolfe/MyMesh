# MyMesh architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        mymesh (CLI)                         │
│  link | shell | cp | desktop | serve | status | devices     │
└─────────────┬───────────────────────────────────────────────┘
              │ control socket / in-proc
┌─────────────▼───────────────────────────────────────────────┐
│                     mymesh-session                          │
│  pairing (SPAKE2) · device store · session handshake        │
└─────────────┬───────────────────────────────────────────────┘
              │
     ┌────────┼────────┬────────────┐
     ▼        ▼        ▼            ▼
 terminal   files   desktop     control
     │        │        │            │
     └────────┼────────┴────────────┘
              │ frames (ALPN mymesh/1)
┌─────────────▼───────────────────────────────────────────────┐
│                       mymesh-net                            │
│  Transport trait ── LocalFabric (tests)                     │
│                  └── IrohEndpoint (prod: QUIC+NAT+relay)    │
└─────────────────────────────────────────────────────────────┘
```

## Pairing (linked devices)

```
Host                         Rendezvous                      Guest
 │  generate code               │                              │
 │  SPAKE2 start                │                              │
 │ ── Spake msg ───────────────►│◄──────── enter code ────────│
 │                              │──────── Spake msg ─────────►│
 │◄─────── Spake msg ───────────│◄──────── Spake msg ─────────│
 │  finish → secret             │                 finish→secret│
 │  IdentityOffer+binder        │                              │
 │─────────────────────────────►│─────────────────────────────►│
 │                              │      IdentityAccept+binder   │
 │◄─────────────────────────────│◄─────────────────────────────│
 │  persist DeviceRecord        │         persist DeviceRecord │
```

After pairing, peers dial by **device id** (public key). No code required again until unlink.

## Session

1. Transport connect (iroh dial / fabric).
2. Control `Hello` with signed identity.
3. Capability negotiation from local device store grants.
4. Open streams: terminal / files / desktop as needed.

## Process model

- **`mymesh serve`**: long-running agent (systemd user unit). Holds identity, accepts sessions.
- **`mymesh shell|cp|desktop`**: client commands that talk to local agent or embed client stack.

## Trust & capabilities

Each `DeviceRecord` stores:

- `DeviceId` + fingerprint  
- capabilities: `terminal` | `files` | `desktop` | `admin`  
- `Trusted` | `Pending` | `Revoked`

## Deployment

| Mode | Description |
|------|-------------|
| Single binary | CLI + agent |
| systemd user | linger-enabled agent |
| Headless | terminal+files only; desktop disabled |
| Omarchy | agent + wayvnc-class desktop backend over MyMesh transport |

## Milestone plan

| M0 | Workspace, crypto, pairing demo, protocol, local fabric | **done** |
| M1 | iroh transport, HTTP/FS mailbox, real `mymesh link` + `serve` | **implemented** |
| M2 | PTY shell end-to-end over iroh | **implemented** |
| M3 | File cp/get/put + progress | **implemented** |
| M4 | Desktop capture backends (X11/Wayland portal) | deferred (after validation) |
| M5 | Packaging: deb/rpm/pkgbuild, `curl | sh`, signed releases | planned |

See [ROADMAP.md](ROADMAP.md) and [M1-M3.md](M1-M3.md) for detail.

## Endpoint ownership (alpha.3+)

Only **`mymesh serve`** may bind the iroh endpoint for a given identity.

- Dial proxy: Unix socket (`daemon.control_socket`, default `$XDG_RUNTIME_DIR/mymesh.sock`)
- CLI/TUI/OpenSSH `proxy-ssh` connect through the proxy (`mymesh_net::connect_mesh`)
- Magic plane TCP/SOCKS/probes use `Arc` shared transport — never a second `bind` of the same secret

See [USAGE.md](USAGE.md) and [ALPHA-3.md](ALPHA-3.md).

