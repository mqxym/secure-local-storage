import "./../setup";
import { StorageService } from "../../src/storage/StorageService";
import { StorageFullError } from "../../src/errors";

describe("StorageService", () => {
  it("get() returns null on invalid JSON", () => {
    const key = "test:storage:invalid";
    localStorage.setItem(key, "{not-json");
    const s = new StorageService(key);
    expect(s.get()).toBeNull();
    localStorage.removeItem(key);
  });

  it("set() wraps quota errors in StorageFullError with size estimate", () => {
    const key = "test:storage:quota";
    const s = new StorageService(key);
    const cfg = {
      header: { v: 2, salt: "", rounds: 1, iv: "iv", wrappedKey: "wk" },
      data: { iv: "iv", ciphertext: "ct" }
    };

    const originalSetItem = localStorage.setItem;
    // @ts-ignore override to simulate quota exceeded
    localStorage.setItem = () => { throw new Error("QuotaExceededError"); };

    try {
      expect(() => s.set(cfg as any)).toThrow(StorageFullError);
    } finally {
      // @ts-ignore restore
      localStorage.setItem = originalSetItem;
      localStorage.removeItem(key);
    }
  });
});

describe("StorageService - quota detection variants", () => {
  it("wraps DOMException(name=QuotaExceededError) as StorageFullError", () => {
    const key = "test:storage:quota:domex";
    const s = new StorageService(key);
    const cfg = {
      header: { v: 2, salt: "", rounds: 1, iv: "iv", wrappedKey: "wk" },
      data: { iv: "iv", ciphertext: "ct" }
    };

    const originalSetItem = localStorage.setItem;
    class QuotaErr extends Error { constructor() { super("quota exceeded"); this.name = "QuotaExceededError"; } }
    // @ts-ignore override
    localStorage.setItem = () => { throw new QuotaErr(); };

    try {
      expect(() => s.set(cfg as any)).toThrow(StorageFullError);
    } finally {
      // @ts-ignore restore
      localStorage.setItem = originalSetItem;
      localStorage.removeItem(key);
    }
  });
  it("wraps quota exceeded when error has numeric code 22", () => {
    const key = "test:storage:quota:code22";
    const s = new StorageService(key);
    const cfg = {
      header: { v: 2, salt: "", rounds: 1, iv: "iv", wrappedKey: "wk" },
      data: { iv: "iv", ciphertext: "ct" }
    };

    const original = localStorage.setItem;
    // @ts-ignore simulate numeric DOMException code path
    localStorage.setItem = () => {
      const e = new Error("dom code 22");
      // @ts-ignore
      e.code = 22;
      throw e;
    };

    try {
      expect(() => s.set(cfg as any)).toThrow(StorageFullError);
    } finally {
      // @ts-ignore
      localStorage.setItem = original;
      localStorage.removeItem(key);
    }
  });
});