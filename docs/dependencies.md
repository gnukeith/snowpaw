# Dependencies

Every direct dependency is pinned to an exact version in the workspace `Cargo.toml`.
`Cargo.lock` pins the rest. `cargo-deny` and `cargo-audit` run in CI.

Adding a dependency needs a reason. Prefer what's already in the build.

| Crate | Used by | Why |
|---|---|---|
| tokio, hyper, hyper-util, axum, tower | server, client, runtime | Async I/O and HTTP. axum and hyper run with default features off. |
| rustls, tokio-rustls (aws-lc-rs provider) | all networked parts | TLS 1.3 only, with hybrid post-quantum key exchange (X25519MLKEM768). |
| aws-lc-rs | server | Already rustls's crypto provider; used directly only for AES-256-GCM, to seal secrets at rest. Same features rustls enables. |
| webpki-roots | server | Mozilla's CA roots, compiled in, for the server's HTTPS calls to model APIs. It doesn't depend on the host's certificate store. |
| rcgen | server | Generates the self-signed certificate at `init`. |
| rusqlite (bundled SQLite) | server | The database. Bundled, so it doesn't depend on the system's SQLite version. |
| argon2 | server | Argon2id password hashing. |
| sha2, getrandom, zeroize | all | Hashes, randomness, wiping secrets. |
| serde, serde_json, toml | all | Strict parsing of frames and config. |
| tracing, tracing-subscriber | server, runtime | Logs (never secrets or message text). |
| rpassword | server | Reads the password from the terminal without echoing it. |
| tokio-tungstenite, futures-util | client, runtime, tests | WebSocket client. |
| slint (software renderer) | client | UI toolkit, used under GPL-3.0-only (see `deny.toml`). The software renderer works without a GPU, e.g. in Qubes VMs. |
| pulldown-cmark | client | Markdown parsing. Already in the build through Slint. |
| rfd | client | The native "choose a picture" dialog (NSOpenPanel; the XDG desktop portal on Linux). The file it returns is opened by the sandboxed worker, not the client. |
| giallo | render worker | Syntax highlighting with Shiki/TextMate grammars. Contains C (Oniguruma), so it runs only in the sandboxed worker. |
| typst, typst-render, typst-layout, typst-assets, mitex | render worker | LaTeX math (converted by mitex, typeset by Typst). Sandboxed worker only. |
| image (png, jpeg, gif, webp; no other formats, no rayon) | render worker | Decodes and re-encodes profile pictures inside the sandbox, with hard limits. Pure-Rust decoders. Already in the build through Typst. |
| rustix, landlock | render worker | Resource limits and the Linux sandbox. |
| tempfile, mitex-spec-gen | tests only | |
| wasmtime (cranelift, runtime; no WASI, component model, async or cache) | agent runtime | Runs plugins with fuel, epoch deadlines and memory limits. The leading Wasm sandbox, from the Bytecode Alliance. |
| wat | tests only | Test plugins written as WebAssembly text. |

## Accepted advisories

`deny.toml` ignores some RustSec advisories, each with a written reason. All except
one are in the render worker's dependencies (Typst 0.15, mitex 0.2), which pin
affected versions:

- two DoS issues in quick-xml, an XML parser Typst uses only for bibliography styles;
- rkyv archive validation, used only for mitex's compiled-in data;
- several unmaintained crates.

None of these code paths are reachable from message content, and the worker runs
sandboxed with CPU, memory and time limits. They're revisited with each Typst/mitex
upgrade.
