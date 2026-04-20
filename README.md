# cli-auth

Pluggable authentication for CLI apps — supports OAuth Device Code, Authorization Code + PKCE, Client Credentials, and Token Exchange (RFC 8693).

## Install

```bash
npm install cli-auth
# or
pnpm add cli-auth
```

Requires Node.js >= 22.

## Quick start

All strategies share the same lifecycle: **create** → **login** → **getToken** → **logout**.

```ts
import { createCliAuth } from "cli-auth";

const auth = createCliAuth({ strategy: "device-code", ... });

await auth.login({ onAuthorization: ... });
const token = await auth.getToken();
await auth.logout();
```

`createCliAuth` returns a strategy-specific auth instance based on the `strategy` field. Each instance exposes:

| Method | Description |
|--------|-------------|
| `login(...)` | Perform the authentication flow (args vary by strategy) |
| `getToken()` | Return a valid access token, auto-refreshing if needed |
| `logout()` | Clear stored tokens |
| `status()` | Return `{ authenticated: boolean, strategy: string }` |

## Storage

Every strategy requires a `storage` object. You control where tokens are persisted:

```ts
import type { Storage } from "cli-auth";

const storage: Storage = {
  load: async () => { /* return saved credential or undefined */ },
  save: async (credential) => { /* persist credential */ },
  clear: async () => { /* remove credential */ },
};
```

### Built-in storage

**memoryStorage** — in-memory, useful for testing or short-lived processes:

```ts
import { memoryStorage } from "cli-auth";

const storage = memoryStorage();
```

**fileStorage** — JSON file with atomic writes and secure permissions (0o600 file, 0o700 directory):

```ts
import { fileStorage } from "cli-auth";

const storage = fileStorage({ dir: "~/.myapp" });
```

**keyringStorage** — system keyring (macOS Keychain, Windows Credential Store, Linux Secret Service) via [`@napi-rs/keyring`](https://github.com/nicolo-ribaudo/keyring-node):

```ts
import { keyringStorage } from "cli-auth";
import { Entry } from "@napi-rs/keyring";

const storage = keyringStorage({
  entry: new Entry("my-app", "tokens"),
});
```

`@napi-rs/keyring` is an optional peer dependency — install it separately:

```bash
pnpm add @napi-rs/keyring
```

### Cross-process locking

When multiple processes share the same storage (e.g. parallel CLI invocations), concurrent token refreshes can cause conflicts. Add a `lock` to serialize refresh operations:

```ts
import { fileStorage, fileLock } from "cli-auth";

const storage = fileStorage({ dir: "~/.myapp" })
  .withLock(fileLock({ lockPath: "~/.myapp/.lock" }));
```

`fileLock` uses atomic file creation (`O_CREAT | O_EXCL`) to ensure only one process refreshes at a time. This works with any storage backend, including keyringStorage:

```ts
import { keyringStorage, fileLock } from "cli-auth";
import { Entry } from "@napi-rs/keyring";

const storage = keyringStorage({ entry: new Entry("my-app", "tokens") })
  .withLock(fileLock({ lockPath: "~/.myapp/.lock" }));
```

You can also implement a custom lock (e.g. Redis) by providing a `lock` method on any storage:

```ts
const storage: Storage = {
  load: async () => { /* ... */ },
  save: async (credential) => { /* ... */ },
  clear: async () => { /* ... */ },
  async lock() {
    // Acquire exclusive lock, return a release function
    await redis.set("myapp:lock", "1", "NX", "EX", 30);
    return async () => { await redis.del("myapp:lock"); };
  },
};
```

## Strategies

### Device Code

Best for CLI tools where users authenticate in a browser on any device. No local server needed.

```ts
const auth = createCliAuth({
  strategy: "device-code",
  provider: {
    metadata: {
      tokenEndpoint: "https://your-tenant.logto.dev/oidc/token",
      deviceAuthorizationEndpoint: "https://your-tenant.logto.dev/oidc/device/auth",
    },
  },
  clientId: "your-client-id",
  storage,
  scope: "openid offline_access profile",  // optional
  resource: "https://your-api-resource",    // optional
  extraParams: { organization_id: "org_1" }, // optional
});

await auth.login({
  onAuthorization: ({ userCode, verificationUri, verificationUriComplete }) => {
    console.log(`Visit: ${verificationUriComplete ?? verificationUri}`);
    console.log(`Enter code: ${userCode}`);
  },
});

const token = await auth.getToken();
```

The `onAuthorization` callback is called once with the user code and verification URL. The library then polls the token endpoint automatically until the user completes authorization.

### Authorization Code + PKCE

Opens a browser for login with a local loopback server to receive the callback. PKCE is handled automatically.

```ts
import { spawn } from "node:child_process";

const auth = createCliAuth({
  strategy: "authorization-code",
  provider: {
    metadata: {
      authorizationEndpoint: "https://your-tenant.logto.dev/oidc/auth",
      tokenEndpoint: "https://your-tenant.logto.dev/oidc/token",
    },
  },
  clientId: "your-client-id",
  storage,
  scope: "openid offline_access profile", // optional
  resource: "https://your-api-resource",   // optional
  callbackPort: 3000,                      // optional, random available port by default
  extraParams: { prompt: "consent" },      // optional
});

await auth.login({
  onAuthorization: (url) => {
    // Open the URL in the user's browser
    spawn("open", [url], { detached: true, stdio: "ignore" }).unref();
  },
});

const token = await auth.getToken();
```

The callback server binds to `127.0.0.1` and shuts down automatically after receiving the authorization code.

### Client Credentials

For machine-to-machine authentication with no user interaction.

```ts
const auth = createCliAuth({
  strategy: "client-credentials",
  provider: {
    metadata: {
      tokenEndpoint: "https://your-tenant.logto.dev/oidc/token",
    },
  },
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  storage,
  resource: "https://your-api-resource",  // optional
  scope: "all",                            // optional
  tokenEndpointAuthMethod: "client_secret_basic", // optional, defaults to "client_secret_post"
});

await auth.login();
const token = await auth.getToken();
```

When the token expires, `getToken()` automatically re-fetches a new one.

### Token Exchange (RFC 8693)

Exchange an existing token (e.g. a personal access token) for an access token.

```ts
const auth = createCliAuth({
  strategy: "token-exchange",
  provider: {
    metadata: {
      tokenEndpoint: "https://your-tenant.logto.dev/oidc/token",
    },
  },
  clientId: "your-client-id",
  subjectToken: "pat_abc123",
  subjectTokenType: "urn:logto:token-type:personal_access_token",
  storage,
  resource: "https://your-api-resource",  // optional
  scope: "openid offline_access profile", // optional
  // For confidential clients:
  // clientSecret: "your-secret",
  // tokenEndpointAuthMethod: "client_secret_basic",
  // For delegation:
  // actorToken: "actor-access-token",
  // actorTokenType: "urn:ietf:params:oauth:token-type:access_token",
});

await auth.login();
const token = await auth.getToken();
```

When the token expires, `getToken()` will use the refresh token if available, otherwise re-exchange the subject token.

## Token refresh

`getToken()` handles token refresh automatically. When the token is within the refresh threshold (default: 300 seconds before expiry), it will:

1. Use the refresh token if available (device-code, authorization-code, token-exchange)
2. Re-fetch via the original grant (client-credentials)
3. Re-exchange the subject token (token-exchange without refresh token)

You can customize the threshold:

```ts
const auth = createCliAuth({
  // ...
  tokenRefreshThreshold: 600, // refresh 600 seconds before expiry
});
```

## Shared config options

These options are available for all strategies:

| Option | Type | Description |
|--------|------|-------------|
| `provider` | `ProviderConfig` | Token endpoint and other provider metadata |
| `clientId` | `string` | OAuth client ID |
| `storage` | `Storage` | Token persistence adapter |
| `resource` | `string?` | Resource indicator (RFC 8707) |
| `scope` | `string?` | Space-separated scopes |
| `extraParams` | `Record<string, string>?` | Additional parameters sent in requests |
| `tokenRefreshThreshold` | `number?` | Seconds before expiry to trigger refresh (default: 300) |

## License

MIT
