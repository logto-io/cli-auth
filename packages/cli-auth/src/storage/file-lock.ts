import { constants } from "node:fs";
import { mkdir, open, unlink } from "node:fs/promises";
import { dirname } from "node:path";
import { setTimeout } from "node:timers/promises";

/**
 * Returns a `lock` function suitable for {@link Storage.lock}, implemented as
 * a sentinel lock file opened with `O_CREAT | O_EXCL`.
 *
 * The call resolves once the lock is held exclusively, returning a release
 * function that removes the sentinel. Contending callers busy-wait with a
 * small sleep between attempts.
 *
 * Atomic only on filesystems where `O_EXCL` is atomic (local filesystems;
 * do not rely on this over networked filesystems like NFS).
 */
export function fileLock(options: {
  /**
   * Path to the sentinel lock file. Typically a sibling of the credentials
   * file (e.g. `credentials.lock`). Must be on a local filesystem.
   */
  lockPath: string;
}): () => Promise<() => Promise<void>> {
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
