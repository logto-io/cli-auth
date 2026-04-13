import "dotenv/config";
import { createCliAuth } from "@logto-io/cli-auth";

const tokenEndpoint = process.env.TOKEN_EXCHANGE_TOKEN_ENDPOINT!;
const clientId = process.env.TOKEN_EXCHANGE_CLIENT_ID!;
const subjectToken = process.env.TOKEN_EXCHANGE_SUBJECT_TOKEN!;

const storage = {
  load: async () => undefined,
  save: async (data: unknown) => {
    console.log("\nToken response:", JSON.stringify(data, null, 2));
  },
  clear: async () => {},
};

// Test 1: Basic token exchange (no resource/scope)
console.log("=== Test 1: Basic token exchange ===");
const auth1 = createCliAuth({
  strategy: "token-exchange",
  provider: { tokenEndpoint, clientId },
  subjectToken,
  subjectTokenType: "urn:logto:token-type:personal_access_token",
  storage,
});

await auth1.login();
console.log("Status:", await auth1.status());
console.log("Access token:", await auth1.getToken());

// Test 2: Token exchange with resource and scope
console.log("\n=== Test 2: With resource and scope ===");
const auth2 = createCliAuth({
  strategy: "token-exchange",
  provider: { tokenEndpoint, clientId },
  subjectToken,
  subjectTokenType: "urn:logto:token-type:personal_access_token",
  scope: "openid offline_access profile",
  storage,
});

await auth2.login();
console.log("Status:", await auth2.status());
console.log("Access token:", await auth2.getToken());
