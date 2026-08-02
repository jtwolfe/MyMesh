# Release handoff

## Retag `v0.1.0-alpha.3`

```bash
git checkout main
git pull
git tag -f -a v0.1.0-alpha.3 -m "v0.1.0-alpha.3"
git push -f origin v0.1.0-alpha.3
```

## Build binary (Linux)

```bash
git checkout v0.1.0-alpha.3
cargo build --release -p mymesh-cli
strip target/release/mymesh   # optional
cp target/release/mymesh ./mymesh-linux-x86_64
# or: mymesh-linux-$(uname -m)
sha256sum mymesh-linux-x86_64 > mymesh-linux-x86_64.sha256
```

## Upload to GitHub Release

```bash
# create/update release notes, then upload assets
gh release edit v0.1.0-alpha.3 --title "v0.1.0-alpha.3" --notes-file docs/RELEASE-NOTES-v0.1.0-alpha.3.md

gh release upload v0.1.0-alpha.3 \
  mymesh-linux-x86_64 \
  mymesh-linux-x86_64.sha256 \
  --clobber
```

Or in the GitHub UI: Releases → `v0.1.0-alpha.3` → Edit → attach binary.

Docs: [USAGE.md](USAGE.md), root [README.md](../README.md), [CHANGELOG.md](../CHANGELOG.md).
