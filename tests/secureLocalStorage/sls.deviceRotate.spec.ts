import "./../setup";
import secureLocalStorage from "../../src";

describe("device mode key rotation", () => {
  it("rotateKeys preserves data while re-encrypting", async () => {
    const sls = secureLocalStorage({ storageKey: "test:device:rotate" });
    await sls.setData({ v: 123 });

    const before = await sls.getData<{ v: number }>();
    expect(before.v).toBe(123);
    before.clear();

    await sls.rotateKeys();

    const after = await sls.getData<{ v: number }>();
    expect(after.v).toBe(123);
    after.clear();
  });
});