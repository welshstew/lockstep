# Security policy

Lockstep handles Vault tokens and secret values, so security reports are very welcome.

## Reporting a vulnerability

Please **don't open a public issue**. Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository. Include what you found, how to
reproduce it, and what an attacker could do with it.

You'll get an acknowledgement within a week. Fixes are released as soon as they're ready,
and reporters are credited unless they'd rather not be.

## Supported versions

Only the latest release (and `main`) gets security fixes.

## Scope

In scope: the Lockstep server and web UI, the container image, and the Helm chart.

Out of scope: the development and demo stacks (`compose.yaml`, `deploy/demo/`), which run
dev-mode Vaults with well-known test credentials on purpose, and vulnerabilities in Vault
itself (report those to HashiCorp).

## How Lockstep is built to be safe

See [docs/security.md](docs/security.md): values are compared on the server and only sent
to the browser on request, sessions are encrypted cookies, writes use check-and-set and are
audit-logged, and every change is scanned (CVEs, secrets, misconfigurations, base image
signatures) before it's merged.
