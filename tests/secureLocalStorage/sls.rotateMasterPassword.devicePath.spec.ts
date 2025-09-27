import "../setup";
import secureLocalStorage from "../../src";
import { LockedError } from "../../src/errors";

describe("rotateMasterPassword in device mode (no prior master) rewires to master mode", () => {
  it("after rotation, unlock with new password works and data preserved", async () => {
    const sls = secureLocalStorage({ storageKey: "test:rotate:device->master" });
    await sls.setData({ v: 42 });

    await sls.rotateMasterPassword("ignored-old", "new-pass");
    expect(sls.isUsingMasterPassword()).toBe(true);

    sls.lock();
    await expect(sls.getData()).rejects.toBeInstanceOf(LockedError);
    await sls.unlock("new-pass");
    const view = await sls.getData<{ v: number }>();
    expect(view.v).toBe(42);
    view.clear();
  });
});