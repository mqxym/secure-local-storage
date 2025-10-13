import "../setup";
import secureLocalStorage from "../../src";
import { ImportError } from "../../src/errors";

describe("importData rejects whitespace-only passwords", () => {
  it("custom-export bundle", async () => {
    const src = secureLocalStorage({ storageKey: "test:import:ws:src" });
    await src.setData({ a: 1 });
    const bundle = await src.exportData("exp-pass");

    const dst = secureLocalStorage({ storageKey: "test:import:ws:dst" });
    await expect(dst.importData(bundle, "   \n\t  ")).rejects.toBeInstanceOf(ImportError);
  });

  it("master-protected bundle", async () => {
    const src = secureLocalStorage({ storageKey: "test:import:ws:src2" });
    await src.setData({ b: 2 });
    await src.setMasterPassword("mp-1");
    const bundle = await src.exportData(); // mPw = true

    const dst = secureLocalStorage({ storageKey: "test:import:ws:dst2" });
    await expect(dst.importData(bundle, "\t  ")).rejects.toBeInstanceOf(ImportError);
  });
});