import "dotenv/config";
import { createCliAuth, memoryStorage } from "cli-auth";

const tokenEndpoint = process.env.TOKEN_EXCHANGE_TOKEN_ENDPOINT!;
const clientId = process.env.TOKEN_EXCHANGE_CLIENT_ID!;
const subjectToken = process.env.TOKEN_EXCHANGE_SUBJECT_TOKEN!;

const provider = {
  metadata: { tokenEndpoint },
};

// Test 1: Basic token exchange (no resource/scope)
console.log("=== Test 1: Basic token exchange ===");
const storage1 = memoryStorage();
const auth1 = createCliAuth({
  strategy: "token-exchange",
  provider,
  clientId,
  subjectToken,
  subjectTokenType: "urn:logto:token-type:personal_access_token",
  storage: storage1,
});

await auth1.login();
console.log("Stored token set:", JSON.stringify(await storage1.load(), null, 2));
console.log("Status:", await auth1.status());
console.log("Access token:", await auth1.getToken());

// Test 2: Token exchange with resource and scope
console.log("\n=== Test 2: With resource and scope ===");
const storage2 = memoryStorage();
const auth2 = createCliAuth({
  strategy: "token-exchange",
  provider,
  clientId,
  subjectToken,
  subjectTokenType: "urn:logto:token-type:personal_access_token",
  scope: "openid offline_access profile",
  storage: storage2,
});

await auth2.login();
console.log("Stored token set:", JSON.stringify(await storage2.load(), null, 2));
console.log("Status:", await auth2.status());
console.log("Access token:", await auth2.getToken());
