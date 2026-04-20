import "dotenv/config";
import { createCliAuth, memoryStorage } from "cli-auth";

const storage = memoryStorage();

const auth = createCliAuth({
  strategy: "client-credentials",
  provider: {
    metadata: {
      tokenEndpoint: process.env.CLIENT_CREDENTIALS_TOKEN_ENDPOINT!,
    },
  },
  clientId: process.env.CLIENT_CREDENTIALS_CLIENT_ID!,
  clientSecret: process.env.CLIENT_CREDENTIALS_CLIENT_SECRET!,
  storage,
  resource: process.env.CLIENT_CREDENTIALS_RESOURCE,
  scope: process.env.CLIENT_CREDENTIALS_SCOPE,
});

console.log("Logging in...");
await auth.login();

console.log("\nStored token set:", JSON.stringify(await storage.load(), null, 2));

const status = await auth.status();
console.log("Status:", status);

const token = await auth.getToken();
console.log("Access token:", token);

console.log("\nLogout...");
await auth.logout();

const statusAfter = await auth.status();
console.log("Status after logout:", statusAfter);
