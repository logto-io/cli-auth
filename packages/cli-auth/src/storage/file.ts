import { mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Storage, TokenSet } from "../types.js";

export function fileStorage<T = TokenSet>(options: { dir: string }): Storage<T> & {
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
