# Install policy (target design)

This describes **intended** behavior for **v0.1.0-alpha.2+**.  
**v0.1.0-alpha.1 does not implement `mymesh install` yet** — you run `serve` manually.

## Defaults

| Choice | Policy |
|--------|--------|
| Preferred install | **User-level** (`systemd --user`), as the user who runs install |
| Default runtime user | **Same user** that ran install — shell/cp run as that uid |
| System-wide install | Optional; **requires root** to install the unit only |
| System runtime | **Must not default to root** — dedicated user or explicit human account |
| Root-as-agent | **Hard warning + explicit override** (e.g. `--i-accept-root-agent`) |

## Lifecycle (planned commands)

```text
mymesh install [--user|--system]
mymesh uninstall [--purge]
mymesh reset [--links|--identity]
```

- **uninstall** — stop service, remove unit/completions; keep data by default  
- **uninstall --purge** — also remove identity, devices, config  
- **reset** — clear links and/or rotate identity without removing the binary  

## Packaging (later)

- One-line installer page (curl \| bash) building or fetching release binaries  
- deb / rpm / AUR (and other distro packages)  
- Completions shipped with packages  

## GUI (later)

- Tray / system bar entry for “features” and service status  
- Does not change the user-default security model  

## Relation to OpenSSH

Remote shell in alpha is **`mymesh shell`**, not `sshd`. Future `.mym` integration may ProxyCommand into the mesh or tunnel to a user `sshd`; policy for “which OS user” remains: **agent uid == action uid** unless a future explicit multi-account design ships.
