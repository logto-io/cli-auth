import type { Storage, TokenSet } from "../types.js";

export type KeyringEntry = {
  getPassword(): string | null;
  setPassword(password: string): void;
  deleteCredential(): boolean;
};

export function keyringStorage<T = TokenSet>(options: { entry: KeyringEntry }): Storage<T> & {
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
