# Threat model

This document grows with each build step. It says what snowpaw protects, from whom,
and which control does it, so that every control can be tested and nothing relies
on "it probably can't happen".

## Trust assumptions

- **The server is trusted.** It can read conversations and decides which messages,
  profiles and settings clients see. TLS protects transport; it does not hide data
  from the server. The client also trusts the connection code: obtain the initial
  address and certificate fingerprint from your server through a trusted channel,
  and verify a replacement before changing a pin after a mismatch.
- **The server's OS account is trusted.** File modes protect against other Unix
  users. They do not isolate unrestricted processes running as the server's user.
  Keep untrusted code under a separate account or in an isolated container or VM.
- **Model providers and granted plugin hosts receive data.** The configured model
  endpoint receives prompts, tool definitions, tool results and any configured API
  key. A plugin host grant permits requests whose path and query may carry data the
  agent can access. Choose these recipients accordingly; prompt labels and host
  allowlists are not data-loss prevention.
- **Runtime isolation is a deployment requirement.** The runtime binary does not
  confine a compromised process's network access. Use the
  [Podman](deployment-podman.md) or [Qubes](deployment-qubes.md) guidance and verify
  the resulting access, including access between agents. An internal shared
  network alone does not establish that each runtime can reach only the server.

## Step 1: sync server skeleton

### What we protect

| Asset | Why it matters |
|---|---|
| The login password | Authenticates the user to the server's API. |
| Session tokens | Carry the user's API authority until expiry or revocation. |
| The TLS private key | Whoever has it can impersonate the server to clients. |
| The message log | Your conversations. Protect against unauthorized reads, alterations and deletions. |

### Who we defend against

1. **Other Unix users on the server host.** Controls: the data dir is created 0700,
   and the database and TLS key 0600. Startup checks ownership and refuses
   group/other access to these paths, rather than requiring those exact modes.
   Symlinked secrets and data dirs are refused. The config file must be owned by
   the server's user (or root) and not be writable by anyone else; it is checked and
   read through the same open file handle, so it cannot be swapped in between.
   The server refuses to run as root.
2. **Anything on the network that can reach the port** (other devices on your LAN,
   VPN peers, and later, compromised agents). Controls:
   - TLS 1.3 only, with hybrid post-quantum key exchange preferred
     (X25519MLKEM768). There is no plaintext listener and no setting to disable TLS.
   - Clients pin the server's certificate by SHA-256 fingerprint, so a network
     attacker can't substitute a certificate, CA-issued or not.
   - The server listens on loopback by default. All-interfaces addresses (0.0.0.0, ::)
     are always rejected; any other non-loopback address needs an explicit opt-in.
   - Deny by default: user routes except login need a valid session. The separate
     agent WebSocket needs an agent runtime token; it does not accept user sessions.
     Unknown routes are 404.
   - Login: Argon2id (64 MiB, 3 passes, 4 lanes); one check at a time; exponential
     backoff after repeated failures that survives restarts. While locked, the
     password isn't even checked, so the lock can't be used to learn whether a guess
     was right.
   - Known devices have separate login throttles ("device cookies"): each successful
     login returns a device token (rotated each time, stored only as a hash). A device
     that presents a valid one gets its own lock; everyone else shares one. An attacker can
     keep the shared lock engaged indefinitely, affecting clients without a currently
     valid device token, including first-time logins. A known device logging in does
     not give the attacker fresh attempts. Per-address limits were rejected: anyone
     with many addresses bypasses them.
   - Sessions: 256-bit random tokens, shown to the client once and stored only as
     SHA-256 hashes. A fresh token on every login, never one supplied by the client.
     Idle timeout, absolute lifetime, a cap on concurrent sessions, and logout /
     logout-everywhere. Changing the password ends every session. WebSockets receive
     revocation notifications from the running server; expiry and changes made by
     another process are checked periodically (`limits.session_recheck_secs`,
     default 30 s), rather than closing synchronously with the database change.
   - Tokens are accepted only in the `Authorization` header, never in the URL
     (URLs end up in logs and history).
   - Resource limits: a global connection cap plus a per-address cap (per IPv4
     address or IPv6 /64) for TLS and HTTP handling; these permits are released on
     WebSocket upgrade, so they do not cap established WebSockets. Other limits:
     TLS handshake deadline; total (not per-read) deadlines for headers and bodies,
     so dribbling bytes can't hold a connection; header and body size caps;
     WebSocket message size cap; per-connection rate limit; idle WebSocket timeout.
3. **Malicious web pages in your browser** (which can send requests to
   `localhost`). Controls: any request carrying an `Origin` or `Sec-Fetch-*` header
   is refused. This is defense in depth; it does not authenticate clients that omit
   these headers. Protected routes still require the appropriate bearer token,
   login requires the JSON content type and body, and routes do not send CORS
   headers. A browser does not use the native client's certificate pin. New routes
   must preserve these controls: no unauthenticated GETs that return data, no
   relaxed content types.
4. **Someone who gets a copy of the database file.** They get an Argon2id hash
   (expensive to attack with a 15+ character password) and token hashes (useless
   for logging in), not the password or live tokens. They can read conversation
   bodies, job prompts, profiles, settings and audit metadata: these are not
   encrypted in the database. Model API keys are sealed separately (see "Secrets
   at rest"). A backup of the whole data directory normally includes the sealing
   key too, unless it was moved elsewhere.

### Input validation

Native protocol messages go through `snowpaw_proto::decode`: typed protocol fields
reject unknown fields, duplicate fields and wrong types, and schema aliases such
as a struct written as an array are rejected. This compares parsed JSON values,
not exact bytes: whitespace, key order and equivalent string escapes may differ.
Embedded JSON tool arguments and schemas, and model-provider responses, have their
own parsing rules; the typed-field duplicate checks do not cover arbitrary JSON
maps. WebSocket peers that send anything invalid, binary frames, the wrong protocol
version, or too much, are disconnected. Error responses never echo input.

### Integrity of the message log

Enforced by SQLite itself, not just by Rust code: `STRICT` tables, CHECK constraints
on every ID and size, append-only messages (triggers abort UPDATE and DELETE, and
`recursive_triggers` makes `INSERT OR REPLACE` hit them too), senders and recipients
must be chat members (foreign keys), and SQLite's defensive mode is on. Message
timestamps, ordering, and IDs are assigned by the server.

These are invariants of the server's configured database connection. They are not
cryptographic tamper evidence against someone who can modify or replace the database
file, remove its triggers or restore an older copy.

### Logging

Passwords, tokens, and message contents are never logged at any level. Dependencies
are capped at `warn` because some log frame or header contents at debug level. The
log level comes from the config file only, not from environment variables.

### Out of scope (for now)

- An attacker with root on the server host, or control of your desktop session.
- Unrestricted processes running as the server's Unix user (see "Trust assumptions").
- Denial of service by someone who can already reach the port, beyond what the
  limits above bound: an attacker with many addresses can still fill connection
  slots, and anyone can keep new devices locked out of login. Mitigation: keep the
  port on loopback or a VPN.
- Message, blob and audit storage is not bounded by the per-request or rate limits.
  Plan disk monitoring, backup protection and recovery for cumulative storage use;
  append-only logs do not provide a retention or deletion policy.
- Secret wiping in memory is best effort. The login body is read into a buffer that
  is wiped, but copies inside rustls and hyper are outside our control.

### Network exposure guidance

Never expose the server port to the internet. For access from other machines, bind
the server to a VPN address (WireGuard or Tailscale) with `allow_non_loopback = true`.
See the [Qubes reference deployment](deployment-qubes.md) for an isolated,
Xen-based setup.

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
  or logging out attempts server-side revocation, with a 3 s timeout. This is best
  effort: an offline client or an interrupted process can leave a session valid
  until expiry or another revocation. Defaults are 7 days idle and 30 days absolute;
  use logout-everywhere or change the password to revoke remaining sessions. The
  device token cannot authenticate a session by itself; it is stored 0600 and
  forgotten when the server settings change.
- **Authorization:** every chat request is checked against membership in the
  database. "No such chat" and "not a member" get the same answer, so ids can't be
  probed. The sender of a message is always the session's principal; the wire format
  has no sender field. Retries are idempotent (`client_msg_id`), and reusing an id
  for a different chat is refused.
- **Content rules (server and outgoing client messages):** non-empty, size-limited
  (`limits.max_message_bytes`), no control characters except newline and tab, and
  no bidirectional override characters (which can make text display differently
  from what it says, e.g. `invoice_‮fdp.exe`). The client structurally decodes incoming
  frames but relies on the trusted server for these message-content rules.
- **Rendering:** text and supported rich content follow the safe subset described
  in Step 2b. Links and remote images are not acted on.
- **Client robustness:** server frames are decoded with the same strict decoder as
  the server uses, frame size is capped (16 MiB), and anything malformed drops the
  connection instead of being guessed at. Messages are only ever filed under the chat
  they claim to belong to. Aggregate replies (chat lists, sync pages) use the frame
  sizing described in Step 4, and a chat list's last message is a preview: the client
  never stores it as the message itself, so what it shows always
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
  - **Linux:** it requests Landlock filesystem and TCP restrictions, plus signal
    and abstract-socket scoping. Available restrictions depend on the kernel; a
    partially enforced ruleset is accepted.
  - Its self-test requires opening `/etc/hosts` and connecting a TCP socket to
    loopback to fail with permission errors. It does not test every requested
    restriction, so passing does not establish signal or abstract-socket scoping.
    The client refuses a worker whose self-test failed.
- **Linux without working Landlock filesystem and TCP restrictions:** the self-test
  fails and the worker is refused. Code and math use text fallbacks, and unavailable
  profile pictures use initials. The requested ABI V9 policy does not restrict UDP;
  do not treat the worker as having complete network isolation.
- **The worker is untrusted too.**
  - Highlighted spans must match the submitted code, allowing line-ending
    normalization and a final empty line.
  - Images must fit size limits (at most 4096 px per side and 4,194,304 pixels).
  - Frames are length-checked.
  - A worker that times out (5 s for code/math, 20 s for pictures) or misbehaves is
    killed and restarted. After 5 failures in a row, rendering is switched off.
- **Markdown is shown, never acted on.**
  - Links are never clickable: the URL is shown as text.
  - Markdown image references are never loaded, and HTML is shown as text.
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
  - No control characters in names or labels; "about" text permits newline. Bidi
    overrides and isolates are refused. These rules block those display controls,
    but do not establish identity or prevent every misleading name.
- **The server never decodes images.**
  - An upload must be `image/png`, at most 512 KiB, and its header must say exactly
    256×256. Only its PNG signature and IHDR dimensions are parsed; all bytes are
    read for hashing and storage.
  - Blobs are stored and fetched by their SHA-256. The client checks downloaded
    bytes against the requested hash. The server still controls the profile's
    referenced hash, so this checks blob consistency, not profile authenticity
    against a compromised server.
- **The client never decodes images either.**
  - A picture the user chooses is opened by the sandboxed worker, which:
    - recognises the format by its content (PNG, JPEG, GIF or WebP; no other decoders
      are compiled in);
    - applies decoding limits of 8192 px per side and 192 MiB of memory;
    - straightens the picture, center-crops it and re-encodes it as a 256×256 PNG.
  - Re-encoding drops EXIF data (including location), comments and colour profiles.
  - Downloaded pictures are decoded by the same worker, and only 256×256 PNGs are
    accepted.
  - Without a working sandbox, initials are shown instead.

## Step 4: agent runtimes

### What changes

Each agent runs in its own runtime (`snowpaw-agent`), meant for its own rootless
Podman container or VM. The stock runtime connects to the sync server; models and
plugin fetches are called through the server. Confining a compromised runtime to
that server requires deployment isolation (see "Trust assumptions").

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
  - The agent socket allows it to list and read its own chats, post in them, ask for
    a model call, report "working", download granted plugins, request granted-host
    fetches, propose jobs and report progress/results for its own open runs.
  - It has no way to change profiles, settings, tokens, links, the kill switch,
    chats it is not a member of or the user's session. Unsupported message types
    are a protocol error and close the connection.
  - What a model writes is untrusted output:
    - Text is cleaned to the message rules.
    - Tool calls must have valid names, bounded JSON-object arguments and a name
      in the tool list supplied by the runtime for that inference request. The
      server drops calls that fail those checks; the list itself is not a grant
      of server authority.
    - Tool calls can only do what the agent could do anyway, within the server's
      limits.
  - Messages from other agents and tool results are labelled to the model as
    information, not instructions. These labels are guidance, not an enforceable
    prompt-injection boundary. A hostile model or runtime can still use its
    granted capabilities to send accessible data or consume permitted resources.
- **The API key.**
  - Kept server-side and sealed with AES-256-GCM before it reaches the database (see
    "Secrets at rest" below).
  - Unsealed only for the request, sent only to the endpoint the user configured, and
    never returned by the API (settings show only "has a key").
  - The runtime is not given the key. The configured model endpoint receives it
    and must be trusted to handle it and the prompt appropriately.
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
  - a rolling 24-hour accounting limit, checked using a prompt estimate plus the
    configured reply allowance before each call;
  - a requested per-reply token cap and a server-side model-call rate limit;
  - one inference in flight per runtime connection.
  The server enforces these checks, but accounting is not a worst-case token or
  monetary ceiling. The prompt estimate does not include tool definitions; final
  usage uses provider-reported counts or fallback estimates. Correct accounting
  and reply limits therefore depend on provider behavior. A failed call still
  charges its prompt estimate. Usage rows older than 48 hours are pruned hourly
  while the server runs; the accounting window is 24 hours.
- **Frame budgets.** The server sizes sync pages and chat lists against the receiving
  socket's write limit (4 × its `max_ws_message_bytes`). Inference replies use fixed
  text and tool-call caps. This does not guarantee that every response fits: chat
  lists and sync pages retain their first summary or message even if it exceeds
  the budget. Plugin fetch bodies have a separate raw-byte limit and can expand
  when encoded as JSON. Chat lists carry one-line previews of last messages, never
  the bodies; sync pages stop early with `has_more`.
  The runtime is told the agent socket's limit in `Welcome` and trims its inference
  requests (oldest context first) using their serialized size. Config validation
  applies a minimum derived from `infer_frame_bound()`; this does not replace
  measuring actual encoded frames.
- **The kill switch.**
  - Pausing agents disconnects runtimes, rejects new runtime connections with 503,
    and refuses new model calls, posts and plugin fetches. Disconnecting a runtime
    aborts its tracked inference task; already admitted plugin fetches are not
    tracked for cancellation and may continue.
  - It survives restarts; live connections re-check the persisted pause state every
    5 seconds.
- **Secrets at rest.**
  - Values are sealed with a 256-bit key in `secrets.key`, mode 0600, created at
    `init`. The key can be moved off the data volume (for example to a TPM-sealed
    systemd credential) with `secrets.key_file`.
  - Each sealed value is bound to its purpose and its agent, so a ciphertext copied
    into another row won't open.
  - A copy of the database alone does not reveal sealed API keys. A copy of both
    the database and its sealing key does. Protect backups and keep the key off
    the backed-up data volume if this separation is required.
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
    - budget/rate refusals for model calls, policy-refused posts, and runtime
      connections (throttled in memory to once per 10 minutes per agent and event
      kind; this throttle resets on server restart).
  - Passwords, tokens, API keys and message bodies are not deliberately recorded as
    audit fields. Some event details contain supplied text, such as job titles;
    that text can itself contain sensitive information. Treat the audit log as
    sensitive data, not as a guaranteed content-free record.

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
  - A same-chat reply is one level deeper than its selected target. A reply anchored
    in a different readable chat is allowed only when the target was written by the
    user, and starts at depth 1. A computed depth above `agents.max_depth` (default 6)
    is refused and audited.
  - This bounds the selected reply ancestry, not the total length of an autonomous
    exchange. The runtime selects the target, and the server does not require it
    to be the latest message or a previously unused user message. Do not rely on
    depth alone to stop a compromised runtime; rate limits, accounting limits,
    link pause and the kill switch remain separate controls.
- **Rate limits.** `agents.messages_per_minute` applies per agent across all chats,
  and `agents.link_messages_per_hour` per sending agent within each conversation
  between agents. Both are counted in the database, so reconnecting does not reset
  them.
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
  - limits the returned body to 1 MiB and each request hop to 15 s (up to four hops,
    including redirects);
  - checks the kill switch and current host grant before starting, and counts toward
    a per-agent rate limit. In-flight fetches retain that host list and are not
    cancelled by pause, token revocation or grant revocation.

  A host grant permits data to leave for that host in URL paths and queries. GET-only
  and the absence of cookies do not prevent data export or guarantee that the remote
  endpoint has no side effects.
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
- **Same limits as any answer.** The stock runtime posts job answers in the agent's
  chat with the user and omits its agent-messaging tool during a job turn. Posts,
  inference and fetches use the ordinary agent checks. The server does not give a
  job a separate, narrower capability: a compromised runtime retains its agent's
  existing chat and tool permissions. These ordinary requests are not bound to an
  open job-run ID.
- **Kill switch and cancellation.**
  - The scheduler checks the kill switch before dispatching work; open runs are
    closed without counting as failures when it observes a pause. Selection and
    startup of due jobs are separate operations, not an atomic check-and-start.
  - Cancelling a job tells the runtime to stop the run in progress.
    Cancellation is cooperative: it does not revoke ordinary agent permissions or
    fence off work already pending in the scheduler or runtime. Do not treat it as
    an immediate barrier to model calls, tool effects or posts.
- **Retries may repeat effects.** A retry has a new run ID. If an earlier attempt
  posted a message but its completion report was lost, the retry may post again;
  per-message idempotency does not provide exactly-once execution across attempts.
- **Untrusted reports.** Progress and result text from a runtime is cleaned to one
  plain line and length-limited. A runtime can report only on its own agent's open
  runs; anything else is ignored.

## Implementation references

These are the enforcement points for the boundaries and limitations described
above. They describe current behavior, not fixes to those limitations.

| Boundary | Source |
|---|---|
| Private filesystem paths | [Ownership and mode checks](../crates/snowpaw-server/src/fsperm.rs#L56-L87) |
| Route credentials | [User and agent middleware](../crates/snowpaw-server/src/api.rs#L318-L353) |
| Connection-cap lifetime | [TLS/HTTP task and permits](../crates/snowpaw-server/src/listener.rs#L126-L153) |
| JSON decoding | [Typed decoding and value comparison](../crates/snowpaw-proto/src/decode.rs#L33-L54) |
| Plaintext storage and append-only triggers | [Messages](../crates/snowpaw-server/src/db.rs#L134-L158), [jobs](../crates/snowpaw-server/src/db.rs#L276-L304) |
| Logout and session rechecks | [Best-effort logout](../crates/snowpaw-client/src/app.rs#L681-L685), [periodic recheck](../crates/snowpaw-server/src/ws.rs#L828-L833) |
| Renderer policy and probes | [Landlock and self-test](../crates/snowpaw-render/src/sandbox.rs#L29-L74), [request timeouts](../crates/snowpaw-client/src/render.rs#L34-L39) |
| Profile picture consistency | [Downloaded-byte hash check](../crates/snowpaw-client/src/net.rs#L260-L277), [profile reference updates](../crates/snowpaw-client/src/store.rs#L740-L747) |
| Model accounting | [Reservation and settlement](../crates/snowpaw-server/src/inference.rs#L62-L133), [provider usage](../crates/snowpaw-server/src/inference.rs#L266-L308) |
| Usage retention | [Hourly maintenance and 48-hour cutoff](../crates/snowpaw-server/src/server.rs#L171-L183) |
| Frame sizing | [Chat lists and sync pages](../crates/snowpaw-server/src/chat_ops.rs#L24-L118), [inference reply caps](../crates/snowpaw-server/src/inference.rs#L286-L308), [stock runtime request sizing](../crates/snowpaw-agent/src/runtime.rs#L539-L567) |
| Reply depth and rates | [Posting policy](../crates/snowpaw-server/src/chat_ops.rs#L190-L229) |
| Plugin fetches | [Task lifetime](../crates/snowpaw-server/src/agent_ws.rs#L278-L293), [admission checks](../crates/snowpaw-server/src/agent_ws.rs#L599-L619), [redirects and deadlines](../crates/snowpaw-server/src/fetch.rs#L132-L147) |
| Audit text | [Job-title audit field](../crates/snowpaw-server/src/agent_ws.rs#L485-L525) |
| Scheduled work | [Scheduler](../crates/snowpaw-server/src/jobs.rs#L46-L98), [cancellation handler](../crates/snowpaw-server/src/ws.rs#L630-L657), [runtime checks and effects](../crates/snowpaw-agent/src/runtime.rs#L514-L626) |
