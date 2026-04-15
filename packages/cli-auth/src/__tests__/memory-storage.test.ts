import { describe, it, expect } from "vitest";
import { memoryStorage, TokenManager } from "../index.js";

describe("memoryStorage", () => {
  it("returns undefined when nothing has been saved", async () => {
    const storage = memoryStorage();
    expect(await storage.load()).toBeUndefined();
  });

  it("save and load round-trips a credential", async () => {
    const storage = memoryStorage<{ accessToken: string; expiresAt: number }>();
    const credential = { accessToken: "tok", expiresAt: 9999999999 };
    await storage.save(credential);
    expect(await storage.load()).toEqual(credential);
  });

  it("clear resets state so load returns undefined", async () => {
    const storage = memoryStorage<{ accessToken: string }>();
    await storage.save({ accessToken: "tok" });
    await storage.clear();
    expect(await storage.load()).toBeUndefined();
  });

  it("each instance is independent", async () => {
    const s1 = memoryStorage<{ accessToken: string }>();
    const s2 = memoryStorage<{ accessToken: string }>();
    await s1.save({ accessToken: "tok1" });
    expect(await s2.load()).toBeUndefined();
  });

  it("default generic works directly with TokenManager", () => {
    // memoryStorage() without explicit generic should be assignable to TokenManager config
    const storage = memoryStorage();
    const manager = new TokenManager({ storage });
    expect(manager).toBeDefined();
  });
});
