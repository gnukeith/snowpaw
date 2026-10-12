# Reference deployment: Qubes OS

Qubes OS gives every part of snowpaw its own Xen virtual machine (a *qube*) on one
computer, with no network between them except what you allow. This is the reference
setup. It needs no extra hardware, no VLANs and no second machine.

```
 snowpaw-client (your app)        snowpaw-agent-<name> (one per agent, netvm: none)
          │  qubes.ConnectTCP 7443          │  qubes.ConnectTCP 7444
          ▼                                 ▼
               snowpaw-server (loopback only)
                      │  netvm: sys-firewall, outbound limited to your model API
                      ▼
                 model API (or a local model qube via qubes.ConnectTCP)
```

- **snowpaw-server.** An AppVM whose firewall allows only the hosts it needs: your
  model API, plus any hosts you'll grant plugins. With a local model in another qube,
  give it no network at all (`netvm` none) and reach the model through
  `qubes.ConnectTCP` too.
- **snowpaw-agent-<name>.** One AppVM per agent, with **no network** (`netvm` none). It
  reaches only the server's agent port, through qrexec. Nothing else is reachable.
- **Your client.** Your usual qube (or a dedicated `snowpaw-client`). It reaches only
  the server's user port.

The server keeps listening on loopback inside its qube. Qubes' `qubes.ConnectTCP`
service connects a port in one qube to `localhost:<port>` in another, and only where
dom0 policy says so.

## 1. Template

Use a minimal template (e.g. `debian-12-minimal`) cloned as `snowpaw-tpl`.
- Install the release binaries in `/usr/local/bin`, after verifying them (see
  [releases.md](releases.md)).
- Install `qubes-core-agent-networking` in the template; it provides `qvm-connect-tcp`.

## 2. The server qube

```bash
qvm-create --template snowpaw-tpl --label red snowpaw-server
qvm-prefs snowpaw-server netvm sys-firewall
qvm-firewall snowpaw-server reset
qvm-firewall snowpaw-server del --rule-no 0
qvm-firewall snowpaw-server add accept dsthost=api.example.com proto=tcp dstports=443
qvm-firewall snowpaw-server add accept specialtarget=dns
qvm-firewall snowpaw-server add drop
```

Run the first three commands in dom0. The firewall rules drop everything except your
model API (and DNS). Replace `api.example.com`, and add a line per plugin host you'll
grant. To use a local model qube instead, set `netvm` to empty and skip the rules.

Inside `snowpaw-server`, keep the data dir on the private volume:

```bash
snowpaw-server init /home/user/snowpaw-data
```

```bash
snowpaw-server set-password --config /home/user/snowpaw-data/server.toml
```

Edit `server.toml`: keep `listen = "127.0.0.1:7443"`, and add the agents-only listener
on another loopback port:

```toml
[server]
listen = "127.0.0.1:7443"
agent_listen = "127.0.0.1:7444"
```

Start it at boot with a user systemd unit (`snowpaw-server run --config …`) or from
`/rw/config/rc.local`.

With a model in another qube (`llm`, running e.g. llama.cpp's server on port 8080),
add this in `snowpaw-server`:

```bash
qvm-connect-tcp 8080:llm:8080
```

Then set the agent's base URL to `http://127.0.0.1:8080/v1`. Plain HTTP is allowed
only to loopback, and here loopback is the qrexec tunnel.

## 3. dom0 policy

Create `/etc/qubes/policy.d/30-snowpaw.policy`:

```
qubes.ConnectTCP +7443 snowpaw-client       @default allow target=snowpaw-server
qubes.ConnectTCP +7444 snowpaw-agent-mochi  @default allow target=snowpaw-server
qubes.ConnectTCP +8080 snowpaw-server       @default allow target=llm
qubes.ConnectTCP *     @anyvm               @anyvm   deny
```

Add one `+7444` line per agent qube. Agents get the agent port only; it serves the
agent endpoint and nothing else (no login, no user API).

## 4. Your client

In the client's qube (persist it in `/rw/config/rc.local`):

```bash
qvm-connect-tcp 7443:snowpaw-server:7443
```

Start the app and paste the connection code that `snowpaw-server connection-code`
prints in the server qube.

## 5. Each agent

```bash
qvm-create --template snowpaw-tpl --label orange snowpaw-agent-mochi
qvm-prefs snowpaw-agent-mochi netvm ''
```

Run both in dom0. In the app, issue the agent's runtime token. Then, inside
`snowpaw-agent-mochi`:

```bash
install -d -m 700 /home/user/snowpaw
```

```bash
umask 077 && cat > /home/user/snowpaw/token
```

Paste the token, press Enter, then Ctrl-D.

Create `/home/user/snowpaw/agent.toml`:

```toml
server = "snowpaw://127.0.0.1:7444#sha256:…"
token_file = "/home/user/snowpaw/token"
```

Use the agent connection code from `snowpaw-server connection-code --agents`.

Add both lines to `/rw/config/rc.local` (or a user systemd unit):

```bash
qvm-connect-tcp 7444:snowpaw-server:7444
```

```bash
snowpaw-agent run --config /home/user/snowpaw/agent.toml
```

The agent qube has no network, so even a fully compromised runtime can reach only
the agent endpoint. Through it, the runtime can act only as that agent, within its
limits.

## Backups

Back up `snowpaw-server`'s private volume. To keep sealed API keys unreadable in a
backup, store the secrets key elsewhere: point `[secrets] key_file` at a file in
another qube's storage, or skip it and re-enter API keys after a restore.

# Alternative: XCP-ng (headless, always on)

For an always-on server box, the same layout works with XCP-ng VMs:

- An **internal network** with no physical interface ("private network") for agents.
  It's a host-only switch: no VLANs, no extra hardware.
- A **server VM** with two NICs:
  - one on the internal network, with `agent_listen` bound to that address;
  - one on your LAN or a WireGuard interface, with `listen` bound to that address and
    `allow_non_loopback = true`. Never expose it to the internet.
- **Agent VMs** with a NIC on the internal network only. Their connection code uses
  the server's internal address and port 7444.
- The **client** connects over WireGuard to the server's `listen` address.

Firewall the server VM's outbound traffic to your model API and granted plugin hosts,
on the hypervisor or inside the VM.
