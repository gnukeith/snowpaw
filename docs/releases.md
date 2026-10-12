# Releases and verifying downloads

Releases are built by GitHub Actions (`.github/workflows/release.yml`) from a version
tag, for Linux (x86_64, aarch64) and macOS (Apple silicon).

Each release has:

- an archive per platform with the server, the agent runtime, the desktop client and
  its render worker;
- for macOS, also `snowpaw.app` as a zip;
- `SHA256SUMS` for every file;
- a signed build-provenance attestation for every file. It is signed keylessly with
  Sigstore, binds the file's hash to the exact workflow run, commit and tag, and is
  logged in the public transparency log.

## Verify before running anything

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

```bash
gh attestation verify snowpaw-0.1.0-x86_64-unknown-linux-gnu.tar.gz --repo gnukeith/snowpaw
```

The first command checks the file is what the release lists. The second checks it was
built by this repository's release workflow from the tagged commit, not uploaded by
hand.

## Build it yourself

Everything is pinned:

- the toolchain, by `rust-toolchain.toml`;
- every crate, by `Cargo.lock` (`--locked`);
- every CI action, by commit SHA;
- container base images, by digest.

```bash
cargo build --release --locked -p snowpaw-server -p snowpaw-agent -p snowpaw-client -p snowpaw-render
```
