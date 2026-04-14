import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileStorage } from "../storage/file.js";

describe("fileStorage", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cli-auth-test-"));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("returns undefined when no file exists", async () => {
    const storage = fileStorage({ dir });
    expect(await storage.load()).toBeUndefined();
  });

  it("save and load round-trips a credential", async () => {
    const storage = fileStorage({ dir });
    const credential = { access_token: "tok", token_type: "Bearer", expires_in: 3600 };
    await storage.save(credential);
    expect(await storage.load()).toEqual(credential);
  });

  it("writes file with 0o600 permissions", async () => {
    const storage = fileStorage({ dir });
    await storage.save({ access_token: "tok", token_type: "Bearer", expires_in: 3600 });

    const { stat } = await import("node:fs/promises");
    const fileStat = await stat(join(dir, "credentials.json"));
    expect(fileStat.mode & 0o777).toBe(0o600);
  });

  it("creates directory with 0o700 permissions if it does not exist", async () => {
    const nestedDir = join(dir, "nested", "deep");
    const storage = fileStorage({ dir: nestedDir });
    await storage.save({ access_token: "tok", token_type: "Bearer", expires_in: 3600 });

    const { stat } = await import("node:fs/promises");
    const dirStat = await stat(nestedDir);
    expect(dirStat.mode & 0o777).toBe(0o700);
  });

  it("throws when file contains invalid JSON", async () => {
    const { writeFile } = await import("node:fs/promises");
    await writeFile(join(dir, "credentials.json"), "not-valid-json");

    const storage = fileStorage({ dir });
    await expect(storage.load()).rejects.toThrow();
  });

  it("clear removes the credential file", async () => {
    const storage = fileStorage({ dir });
    await storage.save({ access_token: "tok", token_type: "Bearer", expires_in: 3600 });
    await storage.clear();
    expect(await storage.load()).toBeUndefined();
  });

  it("clear does not throw when file does not exist", async () => {
    const storage = fileStorage({ dir });
    await expect(storage.clear()).resolves.toBeUndefined();
  });
});
