# cli-auth

Pluggable authentication for CLI apps. Supports OAuth Device Code, Authorization Code + PKCE, Client Credentials, and Token Exchange (RFC 8693).

**User-facing documentation lives in [`packages/cli-auth/README.md`](./packages/cli-auth/README.md)**, which is also what ships to npmjs.com.

## Repository layout

This is a pnpm workspace monorepo.

| Path | Purpose |
|------|---------|
| [`packages/cli-auth`](./packages/cli-auth) | The published `cli-auth` package. Source, tests, build output, and the README users see on npm. |
| [`packages/samples`](./packages/samples) | Runnable example scripts for each strategy (device-code, authorization-code, client-credentials, token-exchange) and a Bun variant. Private, not published. |

## Development

Requires Node.js >= 22 and pnpm 10.

```bash
pnpm install
pnpm -r build
pnpm -r test
pnpm -r typecheck
```

Scripts at the root run recursively across workspaces. To work inside a single package, run the same scripts under `packages/cli-auth` or `packages/samples`.

The test suite also runs under Bun in CI (`bun x vitest run` inside `packages/cli-auth`); see `.github/workflows/main.yml`.

## Running samples

The `samples` package contains one script per strategy. Each script expects a `.env` file with your OAuth client config (see the individual files for required variables).

```bash
cd packages/samples
cp .env.example .env   # if present; otherwise create one
pnpm device-code
pnpm authorization-code
pnpm client-credentials
pnpm token-exchange
pnpm keyring-storage
pnpm bun:authorization-code   # same flow under Bun
```

## License

[MIT](./LICENSE)
