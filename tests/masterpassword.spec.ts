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