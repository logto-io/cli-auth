import { createCliAuth } from "@logto-io/cli-auth";

const auth = createCliAuth({
  strategy: "client-credentials",
  provider: {
    tokenEndpoint: "https://your-tenant.logto.dev/oidc/token",
    clientId: "your-client-id",
    clientSecret: "your-client-secret",
  },
  storage: {
    load: async () => undefined,
    save: async () => {},
    clear: async () => {},
  },
  resource: "https://your-api-resource",
  scope: "all",
});

console.log("Logging in...");
await auth.login();

const status = await auth.status();
console.log("Status:", status);

const token = await auth.getToken();
console.log("Access token:", token);

console.log("\nLogout...");
await auth.logout();

const statusAfter = await auth.status();
console.log("Status after logout:", statusAfter);
