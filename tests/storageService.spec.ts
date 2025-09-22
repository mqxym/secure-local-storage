import "./setup";
import { StorageService } from "../src/storage/StorageService";
import { StorageFullError } from "../src/errors";

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