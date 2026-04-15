/**
 * Standalone demo of keyringStorage.
 *
 * Run: pnpm keyring-storage
 *
 * This script stores a mock credential in the system keyring, reads it back,
 * and then removes it. You can observe the entry appearing and disappearing
 * in your OS credential manager (e.g. macOS Keychain Access).
 */
import { keyringStorage } from "@logto-io/cli-auth";
import { Entry } from "@napi-rs/keyring";

const SERVICE = "logto-cli-auth-sample";
const ACCOUNT = "demo-tokens";

const entry = new Entry(SERVICE, ACCOUNT);
const storage = keyringStorage({ entry });

// 1. Verify empty state
console.log("1. Loading from keyring (should be undefined)...");
const initial = await storage.load();
console.log("   Result:", initial);

// 2. Save a mock credential
const mockCredential = {
  access_token: "eyJhbGciOiJSUzI1NiJ9.mock-access-token",
  token_type: "Bearer",
  expires_in: 3600,
  refresh_token: "mock-refresh-token",
  scope: "openid offline_access profile",
};

console.log("\n2. Saving credential to keyring...");
await storage.save(mockCredential);
console.log("   Saved! Check your OS keyring for service:", SERVICE);

// 3. Load it back
console.log("\n3. Loading credential from keyring...");
const loaded = await storage.load();
console.log("   Result:", JSON.stringify(loaded, null, 2));

// 4. Verify round-trip
const match =
  loaded !== undefined &&
  loaded.access_token === mockCredential.access_token &&
  loaded.refresh_token === mockCredential.refresh_token;
console.log("\n4. Round-trip match:", match ? "YES" : "NO");

// 5. Clear
console.log("\n5. Clearing credential from keyring...");
await storage.clear();
const afterClear = await storage.load();
console.log("   After clear (should be undefined):", afterClear);

console.log("\nDone!");
