import "dotenv/config";
import { createCliAuth, memoryStorage } from "cli-auth";

const storage = memoryStorage();

const auth = createCliAuth({
  strategy: "device-code",
  provider: {
    metadata: {
      deviceAuthorizationEndpoint: process.env.DEVICE_CODE_DEVICE_AUTHORIZATION_ENDPOINT!,
      tokenEndpoint: process.env.DEVICE_CODE_TOKEN_ENDPOINT!,
    },
  },
  clientId: process.env.DEVICE_CODE_CLIENT_ID!,
  storage,
  scope: process.env.DEVICE_CODE_SCOPE,
});

console.log("Starting device code flow...");
await auth.login({
  onAuthorization: ({ userCode, verificationUri, verificationUriComplete }) => {
    console.log("\n--- Action required ---");
    console.log(`Visit: ${verificationUriComplete ?? verificationUri}`);
    console.log(`Enter code: ${userCode}`);
    console.log("-----------------------\n");
  },
});

console.log("\nStored token set:", JSON.stringify(await storage.load(), null, 2));

const status = await auth.status();
console.log("Status:", status);

const token = await auth.getToken();
console.log("Access token:", token);

console.log("\nLogging out...");
await auth.logout();

const statusAfter = await auth.status();
console.log("Status after logout:", statusAfter);
