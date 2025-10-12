import "./../setup";
import { StorageService } from "../../src/storage/StorageService";
import { PersistenceError, StorageFullError } from "../../src/errors";

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
  it("wraps DOMException(name=NS_ERROR_DOM_QUOTA_REACHED) as StorageFullError", () => {
    const key = "test:storage:quota:ns_error";
    const s = new StorageService(key);
    const cfg = {
      header: { v: 2, salt: "", rounds: 1, iv: "iv", wrappedKey: "wk" },
      data: { iv: "iv", ciphertext: "ct" }
    };

    const originalSetItem = localStorage.setItem;
    class NSQuotaErr extends Error { constructor() { super("NS_ERROR_DOM_QUOTA_REACHED"); this.name = "NS_ERROR_DOM_QUOTA_REACHED"; } }
    // @ts-ignore override
    localStorage.setItem = () => { throw new NSQuotaErr(); };

    try {
      expect(() => s.set(cfg as any)).toThrow(StorageFullError);
    } finally {
      // @ts-ignore restore
      localStorage.setItem = originalSetItem;
      localStorage.removeItem(key);
    }
  });

  it("wraps generic 'quota exceeded' messages as StorageFullError", () => {
    const key = "test:storage:quota:message";
    const s = new StorageService(key);
    const cfg = {
      header: { v: 2, salt: "", rounds: 1, iv: "iv", wrappedKey: "wk" },
      data: { iv: "iv", ciphertext: "ct" }
    };

    const originalSetItem = localStorage.setItem;
    // @ts-ignore override
    localStorage.setItem = () => { throw new Error("The quota has been exceeded."); };

    try {
      expect(() => s.set(cfg as any)).toThrow(StorageFullError);
    } finally {
      // @ts-ignore restore
      localStorage.setItem = originalSetItem;
      localStorage.removeItem(key);
    }
  });
});

describe("StorageService - integrity & quota variants", () => {
  it("throws when post-write readback differs (integrity check)", () => {
    const key = "test:storage:integrity";
    const svc = new StorageService(key);
    const cfg = {
      header: { v: 2, salt: "", rounds: 1, iv: "aXY", wrappedKey: "d2s" },
      data: { iv: "aXY", ciphertext: "Y3Q" }
    } as unknown as any;

    const originalSetItem = localStorage.setItem;
    const originalGetItem = localStorage.getItem;

    // Let setItem succeed but corrupt the readback
    // @ts-ignore
    localStorage.setItem = (...args: unknown[]) => originalSetItem.apply(localStorage, args);
    // @ts-ignore
    localStorage.getItem = (_k: string) => "__tampered__";

    try {
      expect(() => svc.set(cfg)).toThrow(PersistenceError);
    } finally {
      // @ts-ignore
      localStorage.setItem = originalSetItem;
      // @ts-ignore
      localStorage.getItem = originalGetItem;
      localStorage.removeItem(key);
    }
  });

  it("quota detection considers Firefox DOMException code 1014", () => {
    const key = "test:storage:quota:1014";
    const svc = new StorageService(key);
    const cfg = {
      header: { v: 2, salt: "", rounds: 1, iv: "aXY", wrappedKey: "d2s" },
      data: { iv: "aXY", ciphertext: "Y3Q" }
    } as unknown as any;

    const original = localStorage.setItem;
    // @ts-ignore simulate Firefox code 1014
    localStorage.setItem = () => {
      const e = new Error("NS_ERROR_DOM_QUOTA_REACHED");
      // @ts-ignore
      e.code = 1014;
      throw e;
    };

    try {
      expect(() => svc.set(cfg)).toThrow(StorageFullError);
    } finally {
      // @ts-ignore
      localStorage.setItem = original;
      localStorage.removeItem(key);
    }
  });
});