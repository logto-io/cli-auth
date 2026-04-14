import { describe, it, expect } from "vitest";
import { memoryStorage } from "../index.js";

describe("memoryStorage", () => {
  it("returns undefined when nothing has been saved", async () => {
    const storage = memoryStorage();
    expect(await storage.load()).toBeUndefined();
  });

  it("save and load round-trips a credential", async () => {
    const storage = memoryStorage();
    const credential = { accessToken: "tok", expiresAt: 9999999999 };
    await storage.save(credential);
    expect(await storage.load()).toEqual(credential);
  });

  it("clear resets state so load returns undefined", async () => {
    const storage = memoryStorage();
    await storage.save({ accessToken: "tok" });
    await storage.clear();
    expect(await storage.load()).toBeUndefined();
  });

  it("each instance is independent", async () => {
    const s1 = memoryStorage();
    const s2 = memoryStorage();
    await s1.save({ accessToken: "tok1" });
    expect(await s2.load()).toBeUndefined();
  });
});
