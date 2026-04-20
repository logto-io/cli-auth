/**
 * Authorization code flow running on the Bun runtime.
 *
 * Run: bun run bun:authorization-code
 *
 * Demonstrates that cli-auth works under Bun:
 *   - Bun auto-loads `.env`, so no `dotenv/config` import is needed.
 *   - `Bun.env` and `Bun.spawn` replace `process.env` and `node:child_process`.
 *   - cli-auth internally uses `node:http` (loopback callback) and `node:crypto`
 *     (PKCE) — both served by Bun's Node compatibility layer.
 */
import { createCliAuth, memoryStorage } from "cli-auth";

const storage = memoryStorage();

const auth = createCliAuth({
  strategy: "authorization-code",
  provider: {
    metadata: {
      authorizationEndpoint: Bun.env.AUTH_CODE_AUTHORIZATION_ENDPOINT!,
      tokenEndpoint: Bun.env.AUTH_CODE_TOKEN_ENDPOINT!,
    },
  },
  clientId: Bun.env.AUTH_CODE_CLIENT_ID!,
  storage,
  scope: Bun.env.AUTH_CODE_SCOPE,
  extraParams: { prompt: "consent" },
});

console.log(`Starting login on Bun ${Bun.version}...`);
await auth.login({
  onAuthorization: (url) => {
    console.log("\nOpening browser for authorization...");
    console.log("URL:", url);
    // open browser (macOS) — Bun.spawn is the Bun-native equivalent of node:child_process.spawn
    Bun.spawn(["open", url], { stdin: "ignore", stdout: "ignore", stderr: "ignore" });
  },
});

console.log("\nStored token set:", JSON.stringify(await storage.load(), null, 2));

const status = await auth.status();
console.log("\nStatus:", status);

const token = await auth.getToken();
console.log("Access token:", token);

console.log("\nLogging out...");
await auth.logout();

const statusAfter = await auth.status();
console.log("Status after logout:", statusAfter);
