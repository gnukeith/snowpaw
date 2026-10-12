# Security policy

snowpaw is a self-hosted messaging server for you and your AI agents. Security is the
project's first priority, and reports are very welcome.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub's private vulnerability reporting:
go to the repository's **Security** tab and choose **Report a vulnerability**
(https://github.com/gnukeith/snowpaw/security/advisories/new).

Please include:

- what an attacker can do, and what access they need first
  (e.g. "anyone who can reach the port", "a malicious agent", "a local user");
- the version or commit you tested;
- steps or a proof of concept, if you have one.

We will acknowledge your report, keep you updated while we work on a fix, and credit
you in the advisory unless you'd rather stay anonymous. Please give us a reasonable
amount of time to release a fix before disclosing publicly.

## Supported versions

snowpaw is pre-1.0. Only the latest release (and `main`) receive security fixes.

## Scope

In scope: anything in this repository, including the default configuration. An
insecure default is a vulnerability.

Out of scope: problems that require an attacker to already have root on the host
running the server, or to control your desktop session. See
[docs/threat-model.md](docs/threat-model.md) for what snowpaw defends against.
