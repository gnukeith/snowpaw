# snowpaw

An open-source, self-hosted, single-user messaging app in the style of Signal, where
your contacts are AI agents. Agents have names and pictures, run on any
OpenAI-compatible model server you choose, can quiz you, can talk to each other when
you let them, and can use plugins you install.

Security is the first priority. See [docs/threat-model.md](docs/threat-model.md) and
[SECURITY.md](SECURITY.md).

**Status:** early, but every part exists. The pieces are:

- the sync server;
- the desktop client, with code highlighting, math and quizzes;
- agent profiles and pictures;
- agent runtimes, with models called through the server;
- agent-to-agent conversations, with depth and rate limits;
- WebAssembly plugins;
- packaging.

Linux and macOS only.

## How it fits together

```
 desktop client ──TLS 1.3, pinned──┐
                                   ▼
                            snowpaw-server ──HTTPS──► your model API
                                   ▲        └─HTTPS─► hosts you allowed plugins to fetch
 agent runtime (one per agent) ────┘
   in its own container or VM, with no other network access
```

- **Sync server** (`crates/snowpaw-server`): the single source of truth. It holds
  your messages, agents, settings, encrypted API keys and the audit log. It calls
  models and fetches URLs on agents' behalf, enforcing every limit.
- **Agent runtime** (`crates/snowpaw-agent`): runs one agent. It holds only that
  agent's token and runs plugins in wasmtime.
- **Desktop client** (`crates/snowpaw-client`, Rust + Slint). Untrusted content
  (code, math, pictures) is rendered in a sandboxed worker (`crates/snowpaw-render`).
- **Protocol** (`crates/snowpaw-proto`) and **plugin SDK**
  (`crates/snowpaw-plugin-sdk`), both Apache-2.0.

More in [docs/architecture.md](docs/architecture.md).

## Quick start

Requires Rust (the version is pinned in `rust-toolchain.toml`).

```bash
cargo build --release --locked
```

### 1. The server

```bash
./target/release/snowpaw-server init ~/.local/share/snowpaw
```

`init` creates the data directory (mode 0700) with a config file, the database, a
self-signed TLS certificate and the key that seals secrets. It prints a
**connection code** (`snowpaw://127.0.0.1:7443#sha256:…`), which tells the app where
the server is and which certificate to trust.

```bash
./target/release/snowpaw-server set-password --config ~/.local/share/snowpaw/server.toml
```

```bash
./target/release/snowpaw-server run --config ~/.local/share/snowpaw/server.toml
```

The server listens on `127.0.0.1:7443` only by default. Every setting, with its
default and allowed range, is in [config/server.example.toml](config/server.example.toml).

### 2. The app

```bash
./target/release/snowpaw
```

Paste the connection code, log in, and you're in your Note to Self. On macOS,
`packaging/macos/build-app.sh` builds `snowpaw.app`.

### 3. An agent

1. In the app, add an agent (name, role, picture).
2. In its settings, choose a model: an OpenAI-compatible base URL (e.g.
   `http://127.0.0.1:11434/v1` for a local Ollama, or an HTTPS API), the model name, an
   API key if needed, and limits. The key is stored encrypted on the server and never
   shown again.
3. Issue a runtime token for the agent, then run its runtime with the two-line config
   the app shows:

```bash
./target/release/snowpaw-agent run --config agent.toml
```

For real use, run each runtime in its own container or VM. See
[docs/deployment-podman.md](docs/deployment-podman.md) and the Qubes OS reference
setup in [docs/deployment-qubes.md](docs/deployment-qubes.md).

### Plugins

Plugins are WebAssembly tools, installed by you and granted per agent. See
[docs/plugins.md](docs/plugins.md) and `examples/plugins/weather`.

## Development

```bash
cargo test --locked
```

The tests include attempts to bypass each security control. CI also runs rustfmt,
clippy, `cargo deny` and a no-unsafe-code check. Releases are built in CI, with
checksums and signed provenance ([docs/releases.md](docs/releases.md)).

Dependencies are few, pinned to exact versions, and each one is justified in
[docs/dependencies.md](docs/dependencies.md).

## License

The protocol crate and the plugin SDK are Apache-2.0, so anyone can build clients,
agents and plugins under any license. Everything else is AGPL-3.0-or-later. See
[LICENSE](LICENSE).
