import type { Storage, TokenSet } from "../types.js";

/**
 * An in-process {@link Storage} backed by a single closure variable.
 *
 * Credentials live for the lifetime of the `Storage` instance and are lost
 * when the process exits. Useful for tests and one-shot CLIs where
 * persistence is explicitly undesired.
 */
export function memoryStorage<T = TokenSet>(): Storage<T> {
  let stored: T | undefined;
  return {
    async load() {
      return stored;
    },
    async save(credential: T) {
      stored = credential;
    },
    async clear() {
      stored = undefined;
    },
  };
}
