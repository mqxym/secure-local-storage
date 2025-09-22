import "./setup";
import secureLocalStorage from "../src";

describe("master password mode", () => {
  it("set, unlock, export/import", async () => {
    const sls = secureLocalStorage({ storageKey: "test:sls-mp" });
    await sls.setData({ value1: 7 });

    await sls.setMasterPassword("correct horse battery staple");
    sls.lock();
    await expect(sls.getData()).rejects.toThrow();

    await sls.unlock("correct horse battery staple");
    const data = await sls.getData<{ value1: number }>();
    expect(data.value1).toBe(7);
    data.clear();

    const exported = await sls.exportData("export-pass");
    const sls2 = secureLocalStorage({ storageKey: "test:sls-mp-2" });
    await sls2.importData(exported, "export-pass");
    const d2 = await sls2.getData<{ value1: number }>();
    expect(d2.value1).toBe(7);
    d2.clear();
  });
});

import { ExportError, ImportError, LockedError, ModeError } from "../src/errors";

describe("master password – additional edge cases", () => {
  it("exportData requires an unlocked session in master mode", async () => {
    const sls = secureLocalStorage({ storageKey: "test:sls-mp-locked" });
    await sls.setData({ v: 1 });
    await sls.setMasterPassword("pw-1");
    sls.lock();
    await expect(sls.exportData("any")).rejects.toBeInstanceOf(LockedError);
  });

  it("setMasterPassword cannot be called twice", async () => {
    const sls = secureLocalStorage({ storageKey: "test:sls-mp-double" });
    await sls.setData({ v: 1 });
    await sls.setMasterPassword("pw-1");
    await expect(sls.setMasterPassword("pw-2")).rejects.toBeInstanceOf(ModeError);
  });

  it("removeMasterPassword requires unlocked session", async () => {
    const sls = secureLocalStorage({ storageKey: "test:sls-mp-remove-locked" });
    await sls.setData({ v: 1 });
    await sls.setMasterPassword("pw-1");
    sls.lock();
    await expect(sls.removeMasterPassword()).rejects.toBeInstanceOf(LockedError);
  });

  it("rotateKeys is forbidden in master mode", async () => {
    const sls = secureLocalStorage({ storageKey: "test:sls-mp-rotate-forbidden" });
    await sls.setData({ v: 1 });
    await sls.setMasterPassword("pw-1");
    await expect(sls.rotateKeys()).rejects.toBeInstanceOf(ModeError);
  });

  it("exportData without a custom password in master mode sets mPw flag and can be re-imported with the master password", async () => {
    const sls = secureLocalStorage({ storageKey: "test:sls-mp-export-mpw" });
    await sls.setData({ z: 9 });
    await sls.setMasterPassword("pw-1");
    const exported = await sls.exportData(); // no custom password -> mPw = true
    const parsed = JSON.parse(exported);
    expect(parsed.header.mPw).toBe(true);

    const sls2 = secureLocalStorage({ storageKey: "test:sls-mp-import-mpw" });
    // wrong master password
    await expect(sls2.importData(exported, "wrong")).rejects.toBeInstanceOf(ImportError);

    // correct master password
    await sls2.importData(exported, "pw-1");
    await sls2.unlock("pw-1"); 
    const data = await sls2.getData<{ z: number }>();
    expect(data.z).toBe(9);
    data.clear();
  });

  it("importData validates inputs (invalid JSON, version mismatch, missing password)", async () => {
    const sls = secureLocalStorage({ storageKey: "test:sls-mp-import-validate" });

    await expect(sls.importData("not-json")).rejects.toBeInstanceOf(ImportError);

    const bogus = JSON.stringify({
      header: { v: 99, salt: "", rounds: 1, iv: "", wrappedKey: "" },
      data: { iv: "", ciphertext: "" }
    });
    await expect(sls.importData(bogus, "x")).rejects.toBeInstanceOf(ImportError);

    // master-protected bundle but no password
    const sls3 = secureLocalStorage({ storageKey: "test:sls-mp-import-need-pass" });
    await sls3.setData({ a: 1 });
    await sls3.setMasterPassword("pw-2");
    const mpExport = await sls3.exportData();
    const sls4 = secureLocalStorage({ storageKey: "test:sls-mp-import-need-pass-2" });
    await expect(sls4.importData(mpExport)).rejects.toBeInstanceOf(ImportError);
  });

  it("import of export-password bundle without password throws ImportError; wrong password currently propagates CryptoError", async () => {
    const sls = secureLocalStorage({ storageKey: "test:sls-export-pass" });
    await sls.setData({ a: 1 });
    const exported = await sls.exportData("exp-pass");

    const sls2 = secureLocalStorage({ storageKey: "test:sls-export-pass-2" });
    await expect(sls2.importData(exported)).rejects.toBeInstanceOf(ImportError);
  });

  it("exportData requires a custom password in device mode", async () => {
    const sls = secureLocalStorage({ storageKey: "test:sls-device-export" });
    await expect(sls.exportData()).rejects.toBeInstanceOf(ExportError);
  });
});