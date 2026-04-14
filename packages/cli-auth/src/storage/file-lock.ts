import { constants } from "node:fs";
import { mkdir, open, unlink } from "node:fs/promises";
import { dirname } from "node:path";
import { setTimeout } from "node:timers/promises";

export function fileLock(options: { lockPath: string }): () => Promise<() => Promise<void>> {
  const { lockPath } = options;

  return async () => {
    await mkdir(dirname(lockPath), { recursive: true, mode: 0o700 });

    // Acquire exclusive lock via O_CREAT | O_EXCL (atomic on local filesystems)
    let handle;
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
    while (true) {
      try {
        handle = await open(lockPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL);
        break;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") {
          await setTimeout(10);
          continue;
        }
        throw error;
      }
    }

    return async () => {
      await unlink(lockPath).catch(() => {});
      await handle.close();
    };
  };
}
