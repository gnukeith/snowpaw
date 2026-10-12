# Threat model

This document grows with each build step. It says what snowpaw protects, from whom,
and which control does it, so that every control can be tested and nothing relies
on "it probably can't happen".

## Step 1: sync server skeleton

### What we protect

| Asset | Why it matters |
|---|---|
| The login password | Grants full control of the server. |
| Session tokens | Each is equivalent to the password until it expires or is revoked. |
| The TLS private key | Whoever has it can impersonate the server to clients. |
| The message log | Your conversations. It must not be readable, alterable, or deletable by anyone else. |

### Who we defend against

1. **Other users and processes on the server host.** Controls: the data dir must
   be mode 0700 and owned by the server's user; the database and TLS key must be
   0600; the server refuses to start otherwise. Symlinked secrets and data dirs are
   refused. The config file must be owned by the server's user (or root) and not be
   writable by anyone else; it is checked and read through the same open file handle,
   so it can't be swapped in between. The server refuses to run as root.
2. **Anything on the network that can reach the port** (other devices on your LAN,
   VPN peers, and later, compromised agents). Controls:
   - TLS 1.3 only, with hybrid post-quantum key exchange preferred
     (X25519MLKEM768). There is no plaintext listener and no setting to disable TLS.
   - Clients pin the server's certificate by SHA-256 fingerprint, so a network
     attacker can't substitute a certificate, CA-issued or not.
   - The server listens on loopback by default. All-interfaces addresses (0.0.0.0, ::)
     are always rejected; any other non-loopback address needs an explicit opt-in.
   - Deny by default: every route except login needs a valid session; unknown routes
     are 404.
   - Login: Argon2id (64 MiB, 3 passes, 4 lanes); one check at a time; exponential
     backoff after repeated failures that survives restarts. While locked, the
     password isn't even checked, so the lock can't be used to learn whether a guess
     was right.
   - Lockout can't be turned against you ("device cookies"): every successful login
     returns a device token (rotated each time, stored only as a hash). A device that
     presents a valid one gets its own lock; everyone else shares one. An attacker can
     keep the shared lock engaged indefinitely, but that only affects devices that
     have never logged in, and a known device logging in doesn't hand the attacker
     fresh attempts. Per-address limits were rejected: anyone with many addresses
     bypasses them.
   - Sessions: 256-bit random tokens, shown to the client once and stored only as
     SHA-256 hashes. A fresh token on every login, never one supplied by the client.
     Idle timeout, absolute lifetime, a cap on concurrent sessions, and logout /
     logout-everywhere. Changing the password ends every session. Open WebSockets
     close as soon as their session ends.
   - Tokens are accepted only in the `Authorization` header, never in the URL
     (URLs end up in logs and history).
   - Resource limits: a global connection cap plus a per-address cap (per IPv4
     address or IPv6 /64) so one peer can't take every slot; TLS handshake deadline;
     total (not per-read) deadlines for headers and bodies, so dribbling bytes can't
     hold a connection; header and body size caps; WebSocket message size cap;
     per-connection rate limit; idle WebSocket timeout.
3. **Malicious web pages in your browser** (which can send requests to
   `localhost`). Controls: any request carrying an `Origin` or `Sec-Fetch-*` header
   is refused; native clients never send them and modern browsers do. Browsers also
   can't complete a TLS handshake with a self-signed, pinned certificate without
   showing a warning first. This is defense in depth: very old browsers send neither
   header, so the real control is that every route except login needs a bearer
   token, login needs a JSON body (which forces a CORS preflight that always fails),
   and no route ever sends CORS headers. New routes must keep it that way: no
   unauthenticated GETs that return data, no relaxed content types.
4. **Someone who gets a copy of the database file.** They get an Argon2id hash
   (expensive to attack with a 15+ character password) and token hashes (useless
   for logging in), not the password or live tokens.

### Input validation

Every message from the network goes through one strict decoder
(`snowpaw_proto::decode`): unknown fields, duplicate keys, wrong types, and
alternate encodings (such as a struct written as an array) are rejected, so each
message has exactly one accepted form. WebSocket peers that send anything invalid,
binary frames, the wrong protocol version, or too much, are disconnected. Error
responses never echo input.

### Integrity of the message log

Enforced by SQLite itself, not just by Rust code: `STRICT` tables, CHECK constraints
on every ID and size, append-only messages (triggers abort UPDATE and DELETE, and
`recursive_triggers` makes `INSERT OR REPLACE` hit them too), senders and recipients
must be chat members (foreign keys), and SQLite's defensive mode is on. Message
timestamps, ordering, and IDs are assigned by the server.

### Logging

Passwords, tokens, and message contents are never logged at any level. Dependencies
are capped at `warn` because some log frame or header contents at debug level. The
log level comes from the config file only, not from environment variables.

### Out of scope (for now)

- An attacker with root on the server host, or control of your desktop session.
- Denial of service by someone who can already reach the port, beyond what the
  limits above bound: an attacker with many addresses can still fill connection
  slots, and anyone can keep new devices locked out of login. Mitigation: keep the
  port on loopback or a VPN.
- Secret wiping in memory is best effort. The login body is read into a buffer that
  is wiped, but copies inside rustls and hyper are outside our control.

### Network exposure guidance

Never expose the server port to the internet. For access from other machines, bind
the server to a VPN address (WireGuard or Tailscale) with `allow_non_loopback = true`.
A reference deployment guide for an isolated, Xen-based setup comes with the
packaging step.

## Step 2: desktop client and chats

### What changes

The client is a second endpoint holding secrets (the session token, the device
token) and showing data from the server. Chats and the message log are now reachable
over the WebSocket.

### Controls

- **Server identity:** the client accepts only the certificate whose SHA-256
  fingerprint you pinned. There is no fallback to certificate authorities and no
  "accept anyway" button; a mismatch is reported as a possible interception.
- **Settings integrity:** whoever can edit the client's settings can point it at their
  own server and fingerprint. The settings folder is created 0700 and files 0600,
  written atomically, and refused if group/other can write them or if they're
  symlinks (checked by inode, so a swap during opening is caught).
- **Session token:** kept in memory only and never written to disk. Closing the app
  or logging out revokes it on the server. The device token, which isn't a credential,
  is stored 0600 and forgotten when the server settings change.
- **Authorization:** every chat request is checked against membership in the
  database. "No such chat" and "not a member" get the same answer, so ids can't be
  probed. The sender of a message is always the session's principal; the wire format
  has no sender field. Retries are idempotent (`client_msg_id`), and reusing an id
  for a different chat is refused.
- **Content rules (server and client):** non-empty, size-limited
  (`limits.max_message_bytes`), no control characters except newline and tab, and
  no bidirectional override characters (which can make text display differently
  from what it says, e.g. `invoice_‮fdp.exe`).
- **Rendering:** everything from the network is displayed as plain text; nothing is
  interpreted as markup, links, or images (rich rendering arrives in Step 2b with its
  own safe subset).
- **Client robustness:** server frames are decoded with the same strict decoder as
  the server uses, frame size is capped (16 MiB), and anything malformed drops the
  connection instead of being guessed at. Messages are only ever filed under the chat
  they claim to belong to. Aggregate replies (chat lists, sync pages) are bounded to
  the socket's write limit on the server side, and a chat list's last message is a
  preview: the client never stores it as the message itself, so what it shows always
  comes from a sync.

### Code safety exception

The client crate uses `unsafe_code = "deny"` instead of `forbid`, because Slint's
generated UI code carries its own unsafe-code allowance for its vtables. Our sources
contain no unsafe code, and CI fails if any appears.


## Step 2b: rich content (code, math)

### What changes

Messages are rendered as a safe Markdown subset, with syntax-highlighted code (giallo,
which includes the Oniguruma regex engine, written in C) and typeset LaTeX math (Typst
and mitex). These are large parsers running on untrusted text.

### Controls

- **Separate, sandboxed process.** Highlighting and math run in `snowpaw-render`,
  started by the client with an empty environment and working directory `/`. Before
  it reads any input it applies CPU, file-size, core-dump and file-descriptor limits.
  - **macOS:** it runs under `sandbox-exec` with a deny-by-default profile.
  - **Linux:** it restricts itself with Landlock (no file access, no TCP, scoped
    signals and abstract sockets).
  - It then proves the sandbox works: opening a file and connecting a socket must both
    be refused. The client refuses a worker whose self-test failed.
- **Linux kernels older than 6.7** can't block network access with Landlock. There
  the self-test fails, and messages show as plain text; the client never runs an
  unsandboxed renderer.
- **The worker is untrusted too.**
  - Highlighted spans must spell out exactly the code that was sent.
  - Images must fit size limits (at most 4096 px per side and 4 megapixels).
  - Frames are length-checked.
  - A worker that times out (5 s) or misbehaves is killed and restarted. After 5
    failures in a row, rendering is switched off.
- **Markdown is shown, never acted on.**
  - Links are never clickable: the URL is shown as text.
  - Images are never loaded, and HTML is shown as text.
  - Styling comes only from tags the client generates itself.

## Step 3: agent profiles and pictures

### What changes

Agents have names, role labels, "about" text and profile pictures. Pictures are
uploaded to and downloaded from the server.

### Controls

- **Only the user edits profiles.** There is no message an agent can send to change
  any profile, including its own.
- **Profile text rules:**
  - Trimmed, length-limited (name 64, role 32, about 500 characters).
  - No control characters, and no bidi overrides or isolates. This stops a name from
    displaying as something else, e.g. pretending to be another agent or the system.
- **The server never decodes images.**
  - An upload must be `image/png`, at most 512 KiB, and its header must say exactly
    256×256. Nothing else of the image is read.
  - Blobs are stored and fetched by their SHA-256. The client checks the hash of what
    it downloads, so neither the server nor anyone in between can swap a picture.
- **The client never decodes images either.**
  - A picture the user chooses is opened by the sandboxed worker, which:
    - recognises the format by its content (PNG, JPEG, GIF or WebP; no other decoders
      are compiled in);
    - caps decoding at 8192 px per side and 192 MiB of memory, so decompression bombs
      are refused before anything is allocated;
    - straightens the picture, center-crops it and re-encodes it as a 256×256 PNG.
  - Re-encoding drops EXIF data (including location), comments and colour profiles.
  - Downloaded pictures are decoded by the same worker, and only 256×256 PNGs are
    accepted.
  - Without a working sandbox, initials are shown instead.

## Step 4: agent runtimes

### What changes

Each agent runs in its own runtime (`snowpaw-agent`), meant for its own rootless
Podman container or VM. Runtimes connect to the sync server, and only to it. Models
are called through the server.

### Assets

- Model API keys.
- The agent's runtime token.
- The conversation history the model sees.
- Your token budget.

### Threats and controls

- **A stolen or leaked runtime token.**
  - Tokens are 256-bit, shown once, and stored by the server only as SHA-256 hashes.
  - A token belongs to exactly one agent. It works only on `/v1/agent/ws`; it isn't
    accepted on the user's socket or HTTP routes, and session tokens aren't accepted
    on the agent socket.
  - Issuing a new token or revoking one cuts off the connected runtime at once.
  - Only one runtime per agent can be connected; a newer one replaces the older.
  - The runtime reads the token from a file that must be private to its user. It is
    never put in config, the command line or the environment, all of which leak more
    easily.
- **A compromised runtime or a hijacked model (prompt injection).**
  - The agent socket offers only: list and read its own chats, post in them, ask for
    a model call, and report "working".
  - It has no way to change profiles, settings, tokens, links, the kill switch, other
    agents' chats or the user's session. Anything else is a protocol error and closes
    the connection.
  - What a model writes is untrusted output:
    - Text is cleaned to the message rules.
    - Tool calls are parsed strictly, and the server drops calls to tools it didn't
      offer.
    - Tool calls can only do what the agent could do anyway, within the server's
      limits.
  - Messages from other agents and tool results are labelled to the model as
    information, not instructions.
- **The API key.**
  - Kept server-side and sealed with AES-256-GCM before it reaches the database (see
    "Secrets at rest" below).
  - Unsealed only for the request, sent only to the endpoint the user configured, and
    never returned by the API (settings show only "has a key").
  - The runtime never sees it, so a compromised runtime can't take it.
- **Model endpoint safety.** The endpoint is set by the user, never by an agent.
  - Calls use TLS 1.3 with Mozilla's CA roots compiled in, or a pinned certificate
    for self-hosted servers.
  - Plain HTTP is allowed only to this machine. That is checked again after DNS
    resolution, so `localhost` can't be pointed elsewhere.
  - Redirects are never followed.
  - Responses are size- and time-limited (`agents.max_inference_response_bytes`,
    `agents.inference_timeout_secs`) and parsed as untrusted data.
  - Model error bodies are never logged (they may echo the prompt).
- **Runaway cost.** Each agent has:
  - a rolling 24-hour token budget, with the worst case reserved before each call;
  - a per-reply token cap and a model-call rate limit;
  - one call in flight at a time.
  These are enforced by the server, where a runtime can't skip them. A failed call
  still charges its prompt estimate (the bytes were sent), so a dead or hostile
  endpoint can't host free retries; usage rows older than the budget window are
  pruned daily, so they can't grow without bound.
- **Frame budgets.** Every aggregate frame the server sends — a sync page, a chat
  list, an inference reply — is bounded to the receiving socket's own write limit
  (4 × its `max_ws_message_bytes`), so the server can never build a frame it can't
  send (that showed up as an endless reconnect loop). Chat lists carry one-line
  previews of last messages, never the bodies; sync pages stop early with `has_more`.
  The runtime is told the agent socket's limit in `Welcome` and trims its inference
  requests (oldest context first) to fit it, and config validation keeps
  `agents.max_ws_message_bytes` at or above the largest rule-following request.
- **The kill switch.**
  - One action stops every agent: runtimes are disconnected, new connections get 503,
    and model calls and posts are refused.
  - It survives restarts, and the command line can set it too; live connections
    re-check every 5 seconds.
- **Secrets at rest.**
  - Values are sealed with a 256-bit key in `secrets.key`, mode 0600, created at
    `init`. The key can be moved off the data volume (for example to a TPM-sealed
    systemd credential) with `secrets.key_file`.
  - Each sealed value is bound to its purpose and its agent, so a ciphertext copied
    into another row won't open.
  - A copy of the database alone reveals no keys.
- **The audit log.**
  - Append-only (enforced by database triggers) and readable from the client.
  - It records:
    - logins and failed logins, with their source address;
    - logging out everywhere;
    - agent creation and changes;
    - token issue and revoke;
    - model setting changes (host and model name, never the key);
    - link and kill-switch changes;
    - depth-limit hits;
    - refused model calls and posts, and runtime connections (each at most once per
      10 minutes per agent).
  - It never contains secrets or message text.

## Step 5: agents talking to each other

### Controls

- **Off by default.** Two agents can talk only after the user allows that pair, which
  creates their chat. Pausing a pair ("Step in") stops both sides at once and keeps
  the history.
- **The user reads along.** The user sees every conversation between agents, live,
  but can't post in them. Agents can't read conversations they aren't part of.
- **Depth limit.**
  - Every post between agents must say which message it answers. The answered message
    must be in a chat the agent can read.
  - Each reply is one level deeper. Past `agents.max_depth` (default 6), the server
    refuses further posts, and the refusal is audited.
  - Replying to an older message never resets the depth.
  - A reply anchored on a message in a *different* chat is how a conversation starts
    or restarts, and is allowed only when that message was written by the user. An
    agent can't cite its own or another agent's messages to reset the clock, so an
    autonomous back-and-forth always grows towards the limit. (Residual: a runtime
    can still cite genuinely new user messages repeatedly; volume is bounded by the
    rate limits.)
- **Rate limits.** `agents.messages_per_minute` applies per agent across all chats,
  and `agents.link_messages_per_hour` per conversation between agents. Both are
  counted in the database, so reconnecting doesn't reset them.
- **Quizzes.** Agents send quizzes; only the user answers them. The server grades the
  answers against the stored quiz; a client that sends its own results is refused.
  The model is told what the server worked out.

## Step 6: plugins

### What changes

Agents get tools from third-party code: WebAssembly plugins, run by agent runtimes.

### Controls

- **Only the user installs and grants.** Model output can't install a plugin, grant
  one, or change what a plugin may do. There is no agent message for any of that.
  - Installing grants nothing.
  - Each agent's grant names the hosts that agent's copy may fetch from. These are a
    subset of what the manifest asks for, checked by the server.
  - Reinstalling clears grants.
  - Everything is audited.
- **The server never runs plugin code.**
  - It stores the module and reads only its manifest section, with a bounded parser.
  - Runtimes download only modules granted to their agent, and check the code against
    the SHA-256 in the grant.
- **Plugins can only compute.** API v1 modules may import nothing (no WASI, no host
  functions); a module that imports anything is refused at load. So a plugin has no
  files, sockets, clock, randomness or environment.
- **Limits.** Each call step runs in a fresh wasmtime instance with:
  - fuel (CPU) and an epoch deadline (5 s wall clock);
  - 64 MiB of memory, a 512 KiB stack, and one instance, memory and table;
  - bounded input (2 MiB) and output (256 KiB).
  Addresses the module returns are bounds-checked by wasmtime before any read or
  write. Tool results given to the model are capped and labelled as untrusted.
- **Network only through the server, SSRF-safe.** A plugin can return "fetch this
  URL"; the server fetches it only if:
  - it's HTTPS on port 443, to a granted host name (never an IP literal);
  - every address the name resolves to is public. Loopback, private, link-local,
    CGNAT, multicast, documentation and reserved ranges are refused, and IPv4-mapped,
    NAT64 and 6to4 forms are unwrapped and checked as IPv4.
  We connect to the checked address, so the name isn't resolved a second time
  (no DNS rebinding). Each fetch:
  - follows at most 3 redirects, each checked the same way;
  - is GET only, with no cookies or credentials;
  - uses TLS 1.3 with public CA roots;
  - is limited to 1 MiB and 15 s;
  - counts toward a per-agent rate limit and stops when the kill switch is on.
- **Unsigned.** Plugins aren't signed yet; the app shows each module's SHA-256 for
  comparison with what the author published.

## Step 7: scheduled jobs

### What changes

Agents do tasks on a schedule, unattended. That makes standing autonomy, persistence
and resource use the risks.

### Controls

- **Only the user schedules.**
  - An agent (meaning its model's output) can only *propose* a job.
  - A proposal is inert until the user approves it in the app.
  - Agents have no message to approve, edit or start jobs. Approving and declining are
    audited.
  - Each agent has at most 5 pending proposals and 32 open jobs.
- **The server owns the schedule.**
  - Jobs and runs live in the database. The server decides when a run starts and
    hands it to the agent's runtime: one run per agent at a time, and only to a
    connected runtime.
  - A run that can't finish is closed as lost and retried with backoff (at most 3
    tries). That covers a disconnected runtime, a missed deadline
    (`agents.job_run_timeout_secs`) and a server restart.
  - Repeating jobs skip missed slots rather than catching up in a burst.
- **Same limits as any answer.** A job run is an ordinary agent turn: it posts only in
  the agent's chat with the user, through the same rate, token-budget and content
  checks. It can't start a conversation with another agent, because there's no user
  message to anchor one.
- **Kill switch and cancellation.**
  - While agents are paused nothing is dispatched; open runs are closed without
    counting as failures.
  - Cancelling a job tells the runtime to stop the run in progress.
- **Untrusted reports.** Progress and result text from a runtime is cleaned to one
  plain line and length-limited. A runtime can report only on its own agent's open
  runs; anything else is ignored.
