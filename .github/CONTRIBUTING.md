# Contributing to hoo

## Development Setup

**Dependencies:**
```bash
# Linux
sudo apt install libpcap-dev

# macOS (included with Xcode tools)
xcode-select --install
```

**Build and run:**
```bash
make build
sudo ./bin/hoo
```

**Run tests:**
```bash
make test
```

## Pull Requests

- Open a PR against `main`
- CI runs automatically: vet, race-detected tests, and a build check on Linux and macOS
- Keep changes focused — one logical change per PR

## Releasing

Releases are tag-driven. Pushing a `v*.*.*` tag triggers the release workflow, which builds binaries for all platforms and publishes them to GitHub Releases automatically.

**Steps to cut a release:**

1. Make sure `main` is in the state you want to release and CI is green.

2. Tag the commit:
   ```bash
   git tag v1.2.3
   git push origin v1.2.3
   ```

3. The release workflow builds Linux (amd64/arm64) and macOS (amd64/arm64) binaries, generates a changelog from git log since the previous tag, attaches `.tar.gz` archives and `.sha256` checksums, and publishes the release.

**Pre-releases** — any tag containing a `-` is automatically marked as a pre-release:
```bash
git tag v1.2.3-beta.1
git push origin v1.2.3-beta.1
```

**Do not** manually create or edit GitHub Releases — let the workflow handle it to keep checksums and artifacts consistent.

## Versioning

hoo follows [Semantic Versioning](https://semver.org):

| Change | Version bump |
|--------|-------------|
| Breaking CLI flag changes, incompatible behavior | Major (`v2.0.0`) |
| New features, new views, new flags | Minor (`v1.1.0`) |
| Bug fixes, performance improvements | Patch (`v1.0.1`) |
