# Release handoff

## Tag `v0.1.0-alpha.3`

```bash
git checkout main
git pull
git tag -f v0.1.0-alpha.3
git push -f origin v0.1.0-alpha.3
```

Optional GitHub release asset:

```bash
cargo build --release -p mymesh-cli
cp target/release/mymesh /tmp/mymesh-linux-x86_64
# gh release upload v0.1.0-alpha.3 /tmp/mymesh-linux-x86_64 --clobber
```

Docs entrypoints: [USAGE.md](USAGE.md), [ALPHA-3.md](ALPHA-3.md), root [README.md](../README.md), [CHANGELOG.md](../CHANGELOG.md).
