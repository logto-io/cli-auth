import { describe, it, expect } from "vitest";
import { keyringStorage } from "../storage/keyring.js";

function fakeEntry(stored?: string) {
  let password: string | null = stored ?? null;
  return {
    getPassword: () => password,
    setPassword: (p: string) => {
      password = p;
    },
    deleteCredential: () => {
      if (password === null) return false;
      password = null;
      return true;
    },
  };
}

describe("keyringStorage", () => {
  it("returns undefined when entry has no password", async () => {
    const storage = keyringStorage({ entry: fakeEntry() });
    expect(await storage.load()).toBeUndefined();
  });

  it("save and load round-trips a credential via JSON serialization", async () => {
    const storage = keyringStorage({ entry: fakeEntry() });
    const credential = { access_token: "tok", token_type: "Bearer", expires_in: 3600 };
    await storage.save(credential);
    expect(await storage.load()).toEqual(credential);
  });

  it("clear removes the credential so load returns undefined", async () => {
    const storage = keyringStorage({ entry: fakeEntry() });
    await storage.save({ access_token: "tok", token_type: "Bearer", expires_in: 3600 });
    await storage.clear();
    expect(await storage.load()).toBeUndefined();
  });

  it("clear does not throw when no credential exists", async () => {
    const storage = keyringStorage({ entry: fakeEntry() });
    await expect(storage.clear()).resolves.toBeUndefined();
  });

  it("load throws when keyring contains invalid JSON", async () => {
    const storage = keyringStorage({ entry: fakeEntry("not-valid-json") });
    await expect(storage.load()).rejects.toThrow();
  });

  describe("withLock", () => {
    it("attaches lock to storage via fluent API", async () => {
      const fakeLock = async () => async () => {};
      const storage = keyringStorage({ entry: fakeEntry() }).withLock(fakeLock);

      expect(storage.lock).toBeDefined();

      // Should still work as normal storage
      const credential = { access_token: "tok", token_type: "Bearer", expires_in: 3600 };
      await storage.save(credential);
      expect(await storage.load()).toEqual(credential);
    });
  });
});
