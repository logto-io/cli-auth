import type { Storage, TokenSet } from "../types.js";

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
