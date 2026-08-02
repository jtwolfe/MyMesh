## MyMesh v0.1.0-alpha.2

Install lifecycle, user systemd service, completions, default TUI, peer metrics.

### Highlights

- `mymesh install` → user unit + `~/.local/bin` + bash/zsh completions  
- `mymesh` (no args) → **TUI**  
- `ping` / `bw` / probe history  
- System install with root warning + non-root runtime user  

### Quick start

```bash
git clone https://github.com/jtwolfe/MyMesh.git && cd MyMesh
git checkout v0.1.0-alpha.2
cargo build --release -p mymesh-cli
./target/release/mymesh install
systemctl --user status mymesh
mymesh   # TUI
```

Link flow unchanged from alpha.1 (arm → link → accept → shell/cp).

### Next

TUI-embedded shell, packages, `.mym` names, desktop.
