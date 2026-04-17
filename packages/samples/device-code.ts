import "dotenv/config";
import { createCliAuth } from "@logto-io/cli-auth";

const auth = createCliAuth({
  strategy: "device-code",
  provider: {
    metadata: {
      deviceAuthorizationEndpoint: process.env.DEVICE_CODE_DEVICE_AUTHORIZATION_ENDPOINT!,
      tokenEndpoint: process.env.DEVICE_CODE_TOKEN_ENDPOINT!,
    },
  },
  clientId: process.env.DEVICE_CODE_CLIENT_ID!,
  storage: {
    load: async () => undefined,
    save: async (data) => {
      console.log("\nToken response:", JSON.stringify(data, null, 2));
    },
    clear: async () => {},
  },
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

const status = await auth.status();
console.log("Status:", status);

const token = await auth.getToken();
console.log("Access token:", token);

console.log("\nLogging out...");
await auth.logout();

const statusAfter = await auth.status();
console.log("Status after logout:", statusAfter);
