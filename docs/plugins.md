# Writing plugins

A plugin gives agents new tools. It's a WebAssembly module, written with the
`snowpaw-plugin-sdk` crate (Apache-2.0, so your plugin can use any license).

## What a plugin can do

Nothing but compute. A plugin imports nothing: it has no files, no network, no clock,
no randomness and no way to reach the agent's runtime or the server. Each call runs
in a fresh instance with a CPU budget, a wall-clock deadline (5 seconds per step),
64 MiB of memory and a small stack.

To use the web, a plugin *asks*: it returns `Reply::Fetch { url, state }`. The
runtime passes the request to the snowpaw server. The server fetches it only if
all of these hold:

- it's `https://` on port 443;
- the host is one that the user allowed for this plugin and this agent;
- the host resolves to the public internet only (no loopback, private, link-local
  or other special addresses);
- the agent is under its fetch rate limit, and agents aren't paused.

Redirects are followed at most 3 times, each checked the same way. The plugin is
then called again with the response (text, at most 1 MiB) and its `state`. At most
4 fetches per tool call.

## Who decides

- Only the user installs plugins (Plugins page in the app), and installing alone
  lets no agent use one.
- The user grants a plugin to an agent, and picks which of the hosts it asks for that
  agent may fetch from (possibly none).
- Reinstalling a plugin with the same name replaces it and removes its grants, since
  the new version may ask for different things.
- Plugins aren't signed yet: the app shows the module's SHA-256 so you can compare it
  with what the author published.

## Writing one

```toml
# Cargo.toml
[lib]
crate-type = ["cdylib"]

[dependencies]
snowpaw-plugin-sdk = "…"
```

```rust
use snowpaw_plugin_sdk::{Call, Fetched, Reply, json};

snowpaw_plugin_sdk::manifest!("../manifest.json");
snowpaw_plugin_sdk::plugin!(handle);

fn handle(call: Call) -> Reply {
    match (call.tool.as_str(), call.fetched) {
        ("lookup", None) => Reply::Fetch {
            url: format!("https://api.example.com/v1/{}", call.args["id"]),
            state: json!({}),
        },
        ("lookup", Some(Fetched::Ok { body, .. })) => Reply::Result(body),
        ("lookup", Some(Fetched::Failed(e))) => Reply::Error(e),
        _ => Reply::Error("unknown tool".into()),
    }
}
```

`manifest.json`:

```json
{
  "api": 1,
  "name": "example",
  "version": "1.0.0",
  "description": "What it's for",
  "tools": [
    {
      "name": "lookup",
      "description": "What the model should know to use it",
      "parameters": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}
    }
  ],
  "capabilities": {"http": ["api.example.com"]}
}
```

Rules:

- `name`: lowercase letters, digits and `-`, at most 24 characters.
- Tool names: lowercase letters, digits and `_`, at most 32 characters, at most 16
  tools. The model sees each tool as `<plugin>__<tool>`.
- Hosts: exact host names (no IP addresses, no wildcards), at most 16.

Build with `cargo build --release --target wasm32-unknown-unknown`
(`rustup target add wasm32-unknown-unknown` once), then install
`target/wasm32-unknown-unknown/release/<name>.wasm` from the app. The modules are
at most 4 MiB. A full example is in `examples/plugins/weather`.

## The API (version 1), for other languages

The module must export `memory` and:

| Export | Signature | Does |
|---|---|---|
| `snowpaw_api` | `() -> i32` | Returns `1`. |
| `snowpaw_buffer` | `(len: i32) -> i32` | Makes room for `len` input bytes; returns their address. |
| `snowpaw_run` | `(len: i32) -> i32` | Handles the input; returns the output length. |
| `snowpaw_output` | `() -> i32` | Address of the output. |

It must import nothing. The manifest goes in a custom section named
`snowpaw-manifest`.

Input:

```json
{"tool": "…", "args": {…}, "state": …, "fetched": null}
```

`fetched` is either `{"status": 200, "content_type": "…", "body": "…"}` or
`{"error": "…"}`.

Output is exactly one of:

- `{"result": "text for the model"}`
- `{"error": "…"}`
- `{"fetch": {"url": "https://…"}, "state": …}`
