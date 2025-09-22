import "fake-indexeddb/auto";

import { webcrypto as nodeCrypto } from "node:crypto";
if (!globalThis.crypto) {
  // @ts-ignore
  globalThis.crypto = nodeCrypto as unknown as Crypto;
}

jest.mock("argon2-browser", () => {
  const te = new TextEncoder();

  async function kdfLikeDigest(
    pass: string,
    salt: Uint8Array,
    opts: { time: number; mem: number; hashLen: number; parallelism: number; type: number }
  ): Promise<Uint8Array> {
    // Build a canonical input buffer from all params
    const header = te.encode(
      `time=${opts.time}|mem=${opts.mem}|len=${opts.hashLen}|par=${opts.parallelism}|type=${opts.type}|`
    );
    const passBytes = te.encode(pass ?? "");
    const base = new Uint8Array(header.length + passBytes.length + salt.length);
    base.set(header, 0);
    base.set(passBytes, header.length);
    base.set(salt, header.length + passBytes.length);

    // First digest
    let seed = new Uint8Array(await crypto.subtle.digest("SHA-256", base));

    // Expand to hashLen by hashing (seed || counter) blocks
    const out = new Uint8Array(opts.hashLen);
    let offset = 0;
    let counter = 0;

    while (offset < out.length) {
      const blockIn = new Uint8Array(seed.length + 4);
      blockIn.set(seed, 0);
      blockIn.set(
        new Uint8Array([
          (counter >>> 24) & 0xff,
          (counter >>> 16) & 0xff,
          (counter >>> 8) & 0xff,
          counter & 0xff
        ]),
        seed.length
      );

      const block = new Uint8Array(await crypto.subtle.digest("SHA-256", blockIn));
      const take = Math.min(block.length, out.length - offset);
      out.set(block.subarray(0, take), offset);
      offset += take;
      counter += 1;

      // Mix the last block back into seed to avoid repeating patterns
      seed = block;
    }

    return out;
  }

  return {
    ArgonType: { Argon2id: 2 },
    hash: async (args: {
      pass: string;
      salt: Uint8Array;
      time: number;
      mem: number;
      hashLen: number;
      parallelism: number;
      type: number;
    }) => {
      // Basic validation like the real lib would do
      if (!args || typeof args.pass !== "string" || !(args.salt instanceof Uint8Array)) {
        throw new Error("argon2 mock: invalid inputs");
      }
      const hash = await kdfLikeDigest(args.pass, args.salt, args);
      return { hash };
    }
  };
});

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