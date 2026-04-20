import { mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Storage, TokenSet } from "../types.js";

/**
 * A file-backed {@link Storage} that stores credentials as JSON in
 * `<dir>/credentials.json`.
 *
 * Writes go through a `.tmp` sibling and an atomic `rename`, so readers
 * never observe a partially written file. The directory is created with
 * mode `0700` and the file with mode `0600`, so other local users cannot
 * read the tokens.
 *
 * The returned object also exposes {@link withLock} for pairing the storage
 * with a cross-process lock (e.g. {@link fileLock}) — needed if more than
 * one CLI invocation may refresh tokens concurrently.
 *
 * @example
 * ```ts
 * import { fileStorage, fileLock } from "cli-auth";
 *
 * const storage = fileStorage({ dir: `${process.env.HOME}/.my-cli` })
 *   .withLock(fileLock({ lockPath: `${process.env.HOME}/.my-cli/credentials.lock` }));
 * ```
 */
export function fileStorage<T = TokenSet>(options: {
  /** Directory to read/write `credentials.json` from. Created if missing. */
  dir: string;
}): Storage<T> & {
  /**
   * Wraps the base storage with a cross-process `lock` implementation. The
   * returned {@link Storage} exposes `lock` on top of the same load/save/clear.
   */
  withLock(lock: () => Promise<() => Promise<void>>): Storage<T>;
} {
  const filePath = join(options.dir, "credentials.json");
  const tmpPath = filePath + ".tmp";

  const storage: Storage<T> = {
    async load() {
      let content: string;
      try {
        content = await readFile(filePath, "utf-8");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") {
          return undefined;
        }
        throw error;
      }
      return JSON.parse(content) as T;
    },
    async save(credential: T) {
      await mkdir(options.dir, { recursive: true, mode: 0o700 });
      await writeFile(tmpPath, JSON.stringify(credential), { mode: 0o600 });
      await rename(tmpPath, filePath);
    },
    async clear() {
      try {
        await unlink(filePath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
          throw error;
        }
      }
    },
  };

  return {
    ...storage,
    withLock(lock: () => Promise<() => Promise<void>>): Storage<T> {
      return { ...storage, lock };
    },
  };
}
