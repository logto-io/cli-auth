import "dotenv/config";
import { createCliAuth, memoryStorage } from "cli-auth";
import { spawn } from "node:child_process";

const storage = memoryStorage();

const auth = createCliAuth({
  strategy: "authorization-code",
  provider: {
    metadata: {
      authorizationEndpoint: process.env.AUTH_CODE_AUTHORIZATION_ENDPOINT!,
      tokenEndpoint: process.env.AUTH_CODE_TOKEN_ENDPOINT!,
    },
  },
  clientId: process.env.AUTH_CODE_CLIENT_ID!,
  storage,
  scope: process.env.AUTH_CODE_SCOPE,
  extraParams: { prompt: "consent" },
});

console.log("Starting login...");
await auth.login({
  onAuthorization: (url) => {
    console.log("\nOpening browser for authorization...");
    console.log("URL:", url);
    // open browser (macOS)
    spawn("open", [url], { detached: true, stdio: "ignore" }).unref();
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
