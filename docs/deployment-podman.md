# Deployment: rootless Podman (Linux)

The server and each agent runtime run as rootless Podman containers, managed by
systemd through Quadlet. Agents sit on an internal network: the only thing they can
reach is the server's agent listener.

```
 host loopback 127.0.0.1:7443 ──► snowpaw-server
                                    ├─ snowpaw-front (10.89.43.0/24): you, model APIs, plugin hosts
                                    └─ snowpaw-agents (10.89.42.0/24, internal): agent listener :7444
 snowpaw-agent-* ──────────────────────┘
   (no other network)
```

## 1. Images

```bash
podman build -f packaging/containers/Containerfile --target server -t localhost/snowpaw-server .
```

```bash
podman build -f packaging/containers/Containerfile --target agent -t localhost/snowpaw-agent .
```

Base images are pinned by digest. The runtime images are distroless (no shell) and
run as a non-root user.

## 2. Initialize the server

```bash
podman volume create snowpaw-data
```

```bash
podman run --rm -v snowpaw-data:/var/lib/snowpaw:Z localhost/snowpaw-server init /var/lib/snowpaw/data
```

```bash
podman run --rm -it -v snowpaw-data:/var/lib/snowpaw:Z localhost/snowpaw-server set-password --config /var/lib/snowpaw/data/server.toml
```

Then edit `server.toml` in the volume:

```toml
[server]
listen = "10.89.43.2:7443"
allow_non_loopback = true
agent_listen = "10.89.42.2:7444"
```

To edit it:

```bash
podman unshare sh -c 'vi "$(podman volume inspect snowpaw-data --format {{.Mountpoint}})/data/server.toml"'
```

The first address is reachable only through the port published on the host's
loopback. The second is on the internal agents' network and serves only the agent
endpoint.

## 3. Quadlet units

```bash
mkdir -p ~/.config/containers/systemd
```

```bash
cp packaging/quadlet/* ~/.config/containers/systemd/
```

```bash
systemctl --user daemon-reload
```

```bash
systemctl --user start snowpaw-server
```

Get the codes:

```bash
podman exec snowpaw-server snowpaw-server connection-code --config /var/lib/snowpaw/data/server.toml
```

```bash
podman exec snowpaw-server snowpaw-server connection-code --agents --config /var/lib/snowpaw/data/server.toml
```

The first is for the app, as `127.0.0.1:7443` (published on your loopback). The second
is for agents.

## 4. Each agent

In the app, add the agent, set its model, and issue its runtime token. Then:

```bash
podman secret create snowpaw-agent-mochi -
```

Paste the token, press Enter, then Ctrl-D.

```bash
mkdir -p ~/.config/snowpaw/agents
```

```bash
printf 'server = "%s"\ntoken_file = "/run/secrets/token"\n' 'snowpaw://10.89.42.2:7444#sha256:…' > ~/.config/snowpaw/agents/mochi.toml
```

Use the agent connection code from step 3.

```bash
cp ~/.config/containers/systemd/snowpaw-agent-example.container ~/.config/containers/systemd/snowpaw-agent-mochi.container
```

Edit the three `CHANGE` lines in the copy, then:

```bash
systemctl --user daemon-reload
```

```bash
systemctl --user start snowpaw-agent-mochi
```

## Hardening in the units

Both containers run with:

- a read-only root filesystem;
- no new privileges and no capabilities;
- a non-root user;
- memory, PID and CPU limits.

The runtime has no writable storage and no network but the internal one. The token
reaches it as a Podman secret (mode 0400), not an environment variable.

To keep the secrets key off the data volume, create it as a Podman secret and set
`[secrets] key_file = "/run/secrets/secrets.key"`.

**Tested status:** the units follow Podman's documented Quadlet options. Check on your
system that `ss -tlnp` shows only `127.0.0.1:7443` on the host. Also check that an
agent container can't reach anything else, e.g.
`podman exec snowpaw-agent-mochi …` has no shell, so try from a debug container on
the same network.
