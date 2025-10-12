import "../setup";
import secureLocalStorage from "../../src";
import { StorageFullError } from "../../src/errors";

describe("SecureLocalStorage - persistence errors bubble as StorageFullError on setData()", () => {
  it("bubbles quota errors from StorageService.set()", async () => {
    const sls = secureLocalStorage({ storageKey: "test:sls:quota:bubble" });
    await sls.setData({ v: 1 });

    const originalSetItem = localStorage.setItem;
    // @ts-ignore simulate quota exceeded
    localStorage.setItem = () => { throw new Error("QuotaExceededError"); };

    try {
      await expect(sls.setData({ v: 2 })).rejects.toBeInstanceOf(StorageFullError);
    } finally {
      // @ts-ignore
      localStorage.setItem = originalSetItem;
    }
  });
});