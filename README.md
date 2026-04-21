# cli-auth

Pluggable authentication for CLI apps. Supports OAuth Device Code, Authorization Code + PKCE, Client Credentials, and Token Exchange (RFC 8693).

## Install

```bash
npm install cli-auth
# or
pnpm add cli-auth
```

Runs on Node.js >= 22 and Bun >= 1.3.

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

Use `memoryStorage` for tests or short-lived processes:

```ts
import { memoryStorage } from "cli-auth";

const storage = memoryStorage();
```

`fileStorage` writes tokens to a JSON file with atomic writes and tight permissions (0o600 on the file, 0o700 on the directory):

```ts
import { fileStorage } from "cli-auth";

const storage = fileStorage({ dir: "~/.myapp" });
```

`keyringStorage` puts tokens in the system keyring (macOS Keychain, Windows Credential Store, Linux Secret Service) via [`@napi-rs/keyring`](https://github.com/nicolo-ribaudo/keyring-node):

```ts
import { keyringStorage } from "cli-auth";
import { Entry } from "@napi-rs/keyring";

const storage = keyringStorage({
  entry: new Entry("my-app", "tokens"),
});
```

`@napi-rs/keyring` is an optional peer dependency. Install it separately:

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

`onAuthorization` fires once with the user code and verification URL. After that, the library polls the token endpoint until the user finishes authorization.

### Authorization Code + PKCE

Opens a browser for login and receives the callback on a local loopback server. The library handles PKCE for you.

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
  callbackPath: "/oauth/callback",         // optional, defaults to "/callback"
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

### Custom callback path

`callbackPath` controls the path portion of the `redirect_uri` sent to the authorization server. The full URI has the form `http://127.0.0.1:<port><callbackPath>`. It defaults to `/callback` and must start with `/` without a query string or fragment. Set it to match whatever path your OAuth client is registered with (e.g. `/oauth/callback`).

Most providers ignore the port when matching loopback redirect URIs, so you can usually register the URI as `http://127.0.0.1/oauth/callback` without a port and let the library pick a random `callbackPort` at runtime. Pin `callbackPort` to a fixed value only if your provider enforces an exact port match.

### Customizing the callback response

By default the loopback server renders a minimal built-in HTML page (`200` on success, `400` on failure) after the browser is redirected back. Provide a `callbackSource` hook to render your own page, redirect to a hosted landing page, or tailor the error message:

```ts
const auth = createCliAuth({
  strategy: "authorization-code",
  // ...
  callbackSource: (res, { success, callbackUrl, verifyError }) => {
    res.writeHead(success ? 200 : 400, {
      "Content-Type": "text/html; charset=utf-8",
    });
    if (success) {
      res.end("<h1>Logged into MyApp</h1><p>You can close this tab.</p>");
    } else if (verifyError) {
      res.end("<h1>Login link expired or tampered</h1>");
    } else {
      const error = callbackUrl.searchParams.get("error") ?? "unknown";
      res.end(`<h1>Authorization failed</h1><p>${error}</p>`);
    }
  },
});
```

The library calls the hook on every callback, successful or failed, passing the raw Node `ServerResponse` and a result object:

- `success`: whether the callback passed local integrity checks (state matched, `code` present, no `error` param).
- `callbackUrl`: the full callback `URL`. Read `code`, `state`, `error`, `error_description` from `callbackUrl.searchParams`.
- `verifyError`: `"state_mismatch"` or `"missing_code"` when a local check failed, otherwise `undefined`. Useful for telling local failures apart from OAuth errors returned by the provider.

Redirecting to a hosted page works too:

```ts
callbackSource: (res, { success }) => {
  res.writeHead(302, {
    Location: success
      ? "https://myapp.com/cli-success"
      : "https://myapp.com/cli-failed",
  });
  res.end();
},
```

If the hook throws, the library writes a minimal `500` fallback to the browser. The CLI-side `login()` result is not affected. Success or failure is decided from `result.success`, not from what the hook did.

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
