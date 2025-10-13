import "../setup";
import {SecureLocalStorage} from "../../src";
import { LockedError } from "../../src/errors";
import { SLS_CONSTANTS } from "../../src/constants";

const MASTER_PASSWORD = "my-secret-password-123";
const STORAGE_KEY = "sls-test";

describe("SecureLocalStorage.isLocked", () => {
  afterEach(() => {
    localStorage.clear();
    indexedDB.deleteDatabase(SLS_CONSTANTS.IDB.DB_NAME);
  });

  it("should be false in device-bound mode", async () => {
    const sls = new SecureLocalStorage({ storageKey: STORAGE_KEY });
    await sls.setData({ foo: "bar" });
    expect(sls.isLocked()).toBe(false);
  });

  it("should be false after setting a master password (session still open)", async () => {
    const sls = new SecureLocalStorage({ storageKey: STORAGE_KEY });
    await sls.setMasterPassword(MASTER_PASSWORD);
    expect(sls.isLocked()).toBe(false);
  });

  it("should be true after lock() is called", async () => {
    const sls = new SecureLocalStorage({ storageKey: STORAGE_KEY });
    await sls.setMasterPassword(MASTER_PASSWORD);
    sls.lock();
    expect(sls.isLocked()).toBe(true);
  });

  it("should be false after unlock() is called", async () => {
    const sls = new SecureLocalStorage({ storageKey: STORAGE_KEY });
    await sls.setMasterPassword(MASTER_PASSWORD);
    sls.lock();
    expect(sls.isLocked()).toBe(true);

    await sls.unlock(MASTER_PASSWORD);
    expect(sls.isLocked()).toBe(false);
  });

  it("should be true in a new session before unlock()", async () => {
    const sls1 = new SecureLocalStorage({ storageKey: STORAGE_KEY });
    await sls1.setMasterPassword(MASTER_PASSWORD);
    await sls1.setData({ foo: "bar" });

    // New instance simulates a new session
    const sls2 = new SecureLocalStorage({ storageKey: STORAGE_KEY });
    // Wait for it to initialize from storage
    // @ts-ignore: Bun is not defined in the test environment
    await new Promise(resolve => setTimeout(resolve, 50));

    expect(sls2.isUsingMasterPassword()).toBe(true);
    expect(sls2.isLocked()).toBe(true);
  });
});


describe("exportData while locked (master mode)", () => {
  it("throws LockedError", async () => {
    const sls = new SecureLocalStorage({ storageKey: "test:locked:export" });
    await sls.setData({ a: 1 });
    await sls.setMasterPassword("pw-1");
    sls.lock();

    await expect(sls.exportData("any-pass")).rejects.toBeInstanceOf(LockedError);
  });
});