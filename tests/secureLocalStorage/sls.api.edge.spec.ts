import "./../setup";
import secureLocalStorage from "../../src";
import { ImportError, LockedError, ModeError, ValidationError } from "../../src/errors";

describe("SecureLocalStorage API - additional edge cases", () => {
  it("unlock() without any stored data throws ImportError", async () => {
    const sls = secureLocalStorage({ storageKey: "test:sls:no-data" });
    await expect(sls.unlock("pw")).resolves.toBeUndefined();
  });

  it("getData() in master mode while locked rejects with LockedError", async () => {
    const sls = secureLocalStorage({ storageKey: "test:sls:locked-master" });
    await sls.setData({ v: 1 });
    await sls.setMasterPassword("pw-1");
    sls.lock();
    await expect(sls.getData()).rejects.toBeInstanceOf(LockedError);
  });

  it("removeMasterPassword() in device mode throws ModeError", async () => {
    const sls = secureLocalStorage({ storageKey: "test:sls:remove-in-device" });
    await sls.setData({ v: 1 });
    await expect(sls.removeMasterPassword()).rejects.toBeInstanceOf(ModeError);
  });

  it("rotateMasterPassword rejects when old password is wrong", async () => {
    const sls = secureLocalStorage({ storageKey: "test:sls:rotate-mp-wrong" });
    await sls.setData({ v: 1 });
    await sls.setMasterPassword("old");
    await expect(sls.rotateMasterPassword("not-old", "new")).rejects.toBeInstanceOf(ValidationError);
  });

  it("export with custom password in master mode imports into device mode", async () => {
    const sls = secureLocalStorage({ storageKey: "test:sls:export-custom" });
    await sls.setData({ a: 7 });
    await sls.setMasterPassword("mpw-1");
    const bundle = await sls.exportData("export-1");

    const sls2 = secureLocalStorage({ storageKey: "test:sls:export-custom:import" });
    await sls2.importData(bundle, "export-1");
    expect(sls2.isUsingMasterPassword()).toBe(false);

    const v = await sls2.getData<{ a: number }>();
    expect(v.a).toBe(7); v.clear();
  });
});