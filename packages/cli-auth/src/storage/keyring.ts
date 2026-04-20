import type { Storage, TokenSet } from "../types.js";

/**
 * Minimal shape of a keyring-backed credential entry — compatible with
 * libraries such as [`@napi-rs/keyring`](https://www.npmjs.com/package/@napi-rs/keyring).
 *
 * Lets the storage delegate persistence to an OS keyring (macOS Keychain,
 * Windows Credential Manager, libsecret, etc.) without taking a hard
 * dependency on any specific keyring library.
 */
export type KeyringEntry = {
  /** Returns the stored credential string, or `null` when no entry exists. */
  getPassword(): string | null;
  /** Replaces the stored credential string. */
  setPassword(password: string): void;
  /** Removes the stored credential. Returns `true` when an entry was deleted. */
  deleteCredential(): boolean;
};

/**
 * An OS-keyring–backed {@link Storage}. Delegates to the provided
 * {@link KeyringEntry}, serializing credentials as JSON.
 *
 * The returned object also exposes {@link withLock} for pairing with a
 * cross-process lock implementation such as {@link fileLock}.
 *
 * @example
 * ```ts
 * import { Entry } from "@napi-rs/keyring";
 * import { keyringStorage } from "cli-auth";
 *
 * const storage = keyringStorage({ entry: new Entry("my-cli", "default") });
 * ```
 */
export function keyringStorage<T = TokenSet>(options: {
  /** The keyring entry to read/write credentials through. */
  entry: KeyringEntry;
}): Storage<T> & {
  /**
   * Wraps the base storage with a cross-process `lock` implementation. The
   * returned {@link Storage} exposes `lock` on top of the same load/save/clear.
   */
  withLock(lock: () => Promise<() => Promise<void>>): Storage<T>;
} {
  const { entry } = options;

  const storage: Storage<T> = {
    async load() {
      const raw = entry.getPassword();
      if (raw === null) return undefined;
      return JSON.parse(raw) as T;
    },
    async save(credential: T) {
      entry.setPassword(JSON.stringify(credential));
    },
    async clear() {
      entry.deleteCredential();
    },
  };

  return {
    ...storage,
    withLock(lock: () => Promise<() => Promise<void>>): Storage<T> {
      return { ...storage, lock };
    },
  };
}
