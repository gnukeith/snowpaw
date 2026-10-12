# Trying it out

A walk through every feature on one machine. Assumes the release build:

```bash
cargo build --release --locked
```

## Upgrading an existing data dir

Stop the old server (Ctrl-C in its terminal) and start the new build with the same
config:

```bash
./target/release/snowpaw-server run --config <DATA_DIR>/server.toml
```

On first start it upgrades the database in place (new tables only; nothing is
rewritten) and creates `secrets.key` in the data dir. Your chats, password and
device logins carry over.

For the new connection-code onboarding, `snowpaw-server connection-code --config …`
prints the code.

## 1. Agents and pictures

1. Click **+** to add an agent: a name, a role, and optionally a picture (any PNG,
   JPEG, GIF or WebP). The picture is cropped and re-encoded in the sandboxed worker.
2. Open the agent's settings and choose a model:
   - A local model: run e.g. Ollama, then set the base URL to
     `http://127.0.0.1:11434/v1` and the model to `llama3.1:8b`. No key needed.
   - A hosted API: `https://…/v1`, the model name and your API key. The key is sealed
     on the server and never shown again.
   - Keep the daily token limit modest at first.
3. Issue a runtime token. The dialog shows the token, the two-line `agent.toml` and the
   command. Then:

```bash
./target/release/snowpaw-agent run --config agent.toml
```

Message the agent. The avatar shows a working dot while it thinks.

## 2. Quizzes

Ask an agent to quiz you on something. It sends a quiz card, which has Quiz and
Flashcards modes. Answer it: the server grades your answers, and the agent's next
reply knows which ones you got wrong.

## 3. Agents talking to each other

1. Create a second agent with its own runtime.
2. In the first agent's settings, allow it to talk to the second.
3. Ask the first agent to check something with the second.

The conversation between them shows up in the sidebar (read-only for you) and as
activity rows in the first agent's chat. "Pause this conversation" stops it. Long
back-and-forths stop by themselves at `agents.max_depth`.

## 4. Plugins

Build the example (it needs `rustup target add wasm32-unknown-unknown` once):

```bash
cargo build --release --target wasm32-unknown-unknown --manifest-path examples/plugins/weather/Cargo.toml
```

1. Go to **Plugins → Install a plugin** and pick
   `examples/plugins/weather/target/wasm32-unknown-unknown/release/snowpaw_weather_plugin.wasm`.
2. Grant it to an agent and tick `api.open-meteo.com`. The server must be able to reach
   the internet.
3. Ask the agent for the current weather somewhere.

## 5. Scheduled jobs

In an agent's details, use **New job** (e.g. "every hour: post a short joke"), or
ask the agent to set something up. If the agent proposes a job, it waits for your
**Approve**. Job cards show progress, the next run, and Cancel.

## 6. Safety controls

- **Pause all agents** (account menu): runtimes are disconnected and stay paused
  across restarts until you resume.
- **Settings → Security log:** logins, token issues, model changes, plugin grants,
  limits hit, and so on. Never secrets or message text.
- Revoke an agent's runtime token: its runtime stops at once.
