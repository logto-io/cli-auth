import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileStorage } from "../storage/file.js";
import { fileLock } from "../storage/file-lock.js";

type TestCredential = { access_token: string; token_type: string; expires_in: number };

describe("fileStorage", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cli-auth-test-"));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("returns undefined when no file exists", async () => {
    const storage = fileStorage<TestCredential>({ dir });
    expect(await storage.load()).toBeUndefined();
  });

  it("save and load round-trips a credential", async () => {
    const storage = fileStorage<TestCredential>({ dir });
    const credential = { access_token: "tok", token_type: "Bearer", expires_in: 3600 };
    await storage.save(credential);
    expect(await storage.load()).toEqual(credential);
  });

  it("writes file with 0o600 permissions", async () => {
    const storage = fileStorage<TestCredential>({ dir });
    await storage.save({ access_token: "tok", token_type: "Bearer", expires_in: 3600 });

    const { stat } = await import("node:fs/promises");
    const fileStat = await stat(join(dir, "credentials.json"));
    expect(fileStat.mode & 0o777).toBe(0o600);
  });

  it("creates directory with 0o700 permissions if it does not exist", async () => {
    const nestedDir = join(dir, "nested", "deep");
    const storage = fileStorage<TestCredential>({ dir: nestedDir });
    await storage.save({ access_token: "tok", token_type: "Bearer", expires_in: 3600 });

    const { stat } = await import("node:fs/promises");
    const dirStat = await stat(nestedDir);
    expect(dirStat.mode & 0o777).toBe(0o700);
  });

  it("throws when file contains invalid JSON", async () => {
    const { writeFile } = await import("node:fs/promises");
    await writeFile(join(dir, "credentials.json"), "not-valid-json");

    const storage = fileStorage<TestCredential>({ dir });
    await expect(storage.load()).rejects.toThrow();
  });

  it("clear removes the credential file", async () => {
    const storage = fileStorage<TestCredential>({ dir });
    await storage.save({ access_token: "tok", token_type: "Bearer", expires_in: 3600 });
    await storage.clear();
    expect(await storage.load()).toBeUndefined();
  });

  it("clear does not throw when file does not exist", async () => {
    const storage = fileStorage<TestCredential>({ dir });
    await expect(storage.clear()).resolves.toBeUndefined();
  });

  describe("withLock", () => {
    it("attaches lock to storage via fluent API", async () => {
      const lockPath = join(dir, "test.lock");
      const storage = fileStorage<TestCredential>({ dir }).withLock(fileLock({ lockPath }));

      expect(storage.lock).toBeDefined();

      const credential: TestCredential = { access_token: "tok", token_type: "Bearer", expires_in: 3600 };
      await storage.save(credential);
      expect(await storage.load()).toEqual(credential);
    });

    it("serializes concurrent calls via lock", async () => {
      const lockPath = join(dir, "test.lock");
      const storage = fileStorage<TestCredential>({ dir }).withLock(fileLock({ lockPath }));
      const order: number[] = [];

      const entered = new Promise<void>((resolve) => {
        void (async () => {
          const release = await storage.lock!();
          order.push(1);
          resolve();
          await new Promise((r) => globalThis.setTimeout(r, 50));
          order.push(2);
          await release();
        })();
      });

      await entered;
      const release = await storage.lock!();
      order.push(3);
      await release();

      expect(order).toEqual([1, 2, 3]);
    });
  });
});
