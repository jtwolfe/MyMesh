# Release handoff (for local Grok Build / maintainer)

Use this if the sandbox cannot finish git tag or GitHub Release, or to re-cut a tag.

## Repo

- **GitHub:** https://github.com/jtwolfe/MyMesh  
- **Tag:** `v0.1.0-alpha.1`  
- **Version in Cargo workspace:** `0.1.0-alpha.1`  
- **Branch:** `main`

## If docs/version are already on main

```bash
cd /path/to/MyMesh
git fetch origin
git checkout main
git pull origin main

# confirm version
grep -A2 'workspace.package' Cargo.toml

# annotated tag (skip if already exists and is correct)
git tag -a v0.1.0-alpha.1 -m "MyMesh v0.1.0-alpha.1 — first alpha (link, shell, cp)"

git push origin v0.1.0-alpha.1

gh release create v0.1.0-alpha.1 \
  --title "v0.1.0-alpha.1" \
  --notes-file docs/RELEASE-NOTES-v0.1.0-alpha.1.md \
  --prerelease
```

## If you must commit gate work locally

```bash
# ensure CHANGELOG.md, README.md, docs/*, Cargo.toml version are present
git add -A
git status
git commit -m "release: v0.1.0-alpha.1 documentation and version bump"
git push origin main
# then tag + gh release as above
```

## Optional: attach Linux binary

```bash
cargo build --release -p mymesh-cli
cp target/release/mymesh mymesh-linux-x86_64
gh release upload v0.1.0-alpha.1 mymesh-linux-x86_64 --clobber
```

## Verify

```bash
gh release view v0.1.0-alpha.1
git ls-remote --tags origin | grep alpha.1
```

## Do not

- Mark this release as “Latest” production without prerelease flag  
- Enable CI without reviewing the workflow  
- Claim systemd install exists in alpha.1 notes  
