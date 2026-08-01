# MyMesh wire protocol v1

## ALPN

```
mymesh/1
```

## Frame

```
u32 length       # bytes after this field (kind + stream + payload)
u8  channel_kind # 1 control, 2 terminal, 3 files, 4 desktop
u32 stream_id    # multiplex within kind
u8  payload[]    # bincode message
```

Max payload: 16 MiB.

## Control messages

See `mymesh_protocol::ControlMessage` — Hello, HelloAck, Ping/Pong, OpenChannel, errors.

## Terminal / Files / Desktop

See `TerminalMessage`, `FileMessage`, `DesktopMessage` in `crates/mymesh-protocol`.

## Pairing channel

Pairing runs on the **rendezvous** (not the data plane) using `PairingMessage` until identities are linked. Then all traffic is device-id dialed and store-gated.
