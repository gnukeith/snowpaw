# Architecture

## Components and trust

| Component | Runs where | Holds | Talks to |
|---|---|---|---|
| `snowpaw-server` | One per installation, on loopback or a private network | Messages, profiles, settings, the audit log; your password hash; agents' API keys (sealed); plugin modules | Clients and runtimes (it listens); model APIs and granted plugin hosts (it calls out) |
| `snowpaw` (desktop client) | Your desktop | Your session token (memory only), its settings and pins | The server only |
| `snowpaw-render` | Started by the client, sandboxed | Nothing | Its parent only, over stdin/stdout |
| `snowpaw-agent` | One per agent, in its own container or VM | That agent's runtime token | The server only |
| Plugins | Inside a runtime, in wasmtime | Nothing | Nothing (they ask the runtime, which asks the server) |

The server is the only component that decides anything. Clients and runtimes ask; the
server checks who is asking and whether they may, every time.

## Protocols

All connections use TLS 1.3 with hybrid post-quantum key exchange. Clients and
runtimes pin the server's certificate by SHA-256. There is no fallback to certificate
authorities.

- `POST /v1/login`, `/v1/logout`, `/v1/logout-all`: the user's sessions (Argon2id,
  rate limited, rotated).
- `GET /v1/ws`: the user's WebSocket.
  - Chats and messages.
  - Agent management: profiles, settings, runtime tokens, links, plugins and grants.
  - The kill switch and the audit log.
- `GET /v1/agent/ws`: a runtime's WebSocket, authenticated by that agent's token. It
  can only read and post in the agent's chats, ask for model calls, download granted
  plugins, ask for fetches, and report "working".
- `POST /v1/blobs`, `GET /v1/blobs/<sha256>`: profile pictures (256×256 PNG),
  content-addressed.
- `POST /v1/plugins`: install a plugin module.

Frames are canonical JSON with a version, decoded strictly. Unknown fields, duplicate
keys or anything malformed close the connection. Types are in `crates/snowpaw-proto`.

## What happens when you send a message

1. The client posts to a chat with a client-chosen id. Retries are safe because the
   server deduplicates.
2. The server checks you're a member, validates the content, stores it in the
   append-only log, and pushes it to every window and to the agent's runtime.
3. The runtime decides to answer. It builds the context: the agent's instructions,
   then recent messages, with other agents' messages labelled as untrusted. It asks
   the server to run the model.
4. The server checks the kill switch, the agent's model settings, its rate limit and
   its token budget. It unseals the API key, calls the model API (TLS 1.3, no
   redirects, size and time limits), and records the usage.
5. If the model calls tools (a quiz, a message to another agent, a plugin), the
   runtime runs them within the agent's permissions and asks again.
6. The runtime posts the reply. It goes through the same checks as any message, plus
   agent rate and depth limits.

## Data at rest

Everything is in one SQLite database in the data directory (mode 0700):

- STRICT tables with CHECK constraints and foreign keys.
- The message log and the audit log are append-only (enforced by triggers).
- Secret values (model API keys) are sealed with AES-256-GCM, using a key kept in
  `secrets.key` or a file you point to.
- Tokens are stored only as SHA-256 hashes.

The client stores its settings (0600) and never stores your session token.
