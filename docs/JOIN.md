# Device linking (default)

## Model

1. Host runs `mymesh serve` and arms joins: `mymesh connect-request allow`
2. Joiner runs `mymesh link <host-id>`
3. Host reviews: `mymesh requests list` → `mymesh requests accept <id>`
4. Arm **auto-disables** after accept
5. Both store Trusted device records; later `shell` / `cp` dial by id over iroh

While **disarmed**, join attempts from unknown devices are rejected.

## Device ids

| Form | Example |
|------|---------|
| Hex (canonical) | 64 hex chars |
| Words (BIP39, 24) | wallet-style English mnemonic of the same 32 bytes |
| URI (QR-ready) | `mymesh:v1:join:<hex>` |

```bash
mymesh id
mymesh id --words
mymesh id --uri
```

## Advanced

- SPAKE short code + local FS mailbox: `mymesh link --local` / `mymesh link --code … --local`
- HTTP mailbox: `MYMESH_MAILBOX=http://…` with SPAKE flags
