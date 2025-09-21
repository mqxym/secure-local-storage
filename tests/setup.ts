import "fake-indexeddb/auto";

import { webcrypto as nodeCrypto } from "node:crypto";
if (!globalThis.crypto) {
  // @ts-ignore
  globalThis.crypto = nodeCrypto as unknown as Crypto;
}

jest.mock("argon2-browser", () => ({
  ArgonType: { Argon2id: 2 },
  hash: async () => {
    return { hash: new Uint8Array(32) }; // dummy 32-byte hash
  }
}));

if (typeof globalThis.localStorage === "undefined") {
  class MemoryStorage implements Storage {
    private map = new Map<string, string>();
    get length() { return this.map.size; }
    clear() { this.map.clear(); }
    getItem(key: string) { return this.map.has(key) ? this.map.get(key)! : null; }
    key(index: number) { return Array.from(this.map.keys())[index] ?? null; }
    removeItem(key: string) { this.map.delete(key); }
    setItem(key: string, value: string) { this.map.set(key, String(value)); }
  }
  // @ts-ignore
  globalThis.localStorage = new MemoryStorage();
}