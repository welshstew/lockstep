# Contributing

Thanks for your interest in Lockstep. Bug reports, ideas and pull requests are welcome.

## Before you start

- **Bugs and ideas:** open an issue first, so we can agree on the approach before you write code.
- **Security issues:** don't open an issue; see [SECURITY.md](SECURITY.md).

## Development

Everything runs in containers (Podman or Docker). [docs/development.md](docs/development.md)
has the details:

```sh
make up        # two Vaults, Dex, seed data and the app on http://localhost:8080
make test      # backend tests against the seeded Vaults
make e2e       # browser end-to-end tests
make scan      # the same security gate CI runs
make chart-check
```

## Pull requests

- Keep each pull request to one change, with tests for new behaviour.
- CI must pass: security scan, chart checks and end-to-end tests.
- Never put real secrets, tokens or internal hostnames in code, tests or fixtures.
- Values must never be logged, and must only reach the browser when the user asks to see them.

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
