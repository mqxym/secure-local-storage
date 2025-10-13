import "../setup";
import secureLocalStorage from "../../src";
import { ImportError, ExportError } from "../../src/errors";

describe("import/export additional validation", () => {
  it("importData rejects invalid base64 in data section", async () => {
    const sls = secureLocalStorage({ storageKey: "test:import:bad-data-b64" });
    const bad = JSON.stringify({
      header: { v: 2, salt: "", rounds: 1, iv: "YWJj", wrappedKey: "YWJj" },
      data: { iv: "###", ciphertext: "!!!" }
    });
    await expect(sls.importData(bad, "x")).rejects.toBeInstanceOf(ImportError);
  });

  it("exportData rejects whitespace-only custom password", async () => {
    const sls = secureLocalStorage({ storageKey: "test:export:spaces" });
    await sls.setData({ v: 1 });
    await expect(sls.exportData("   \n\t ")).rejects.toBeInstanceOf(ExportError);
  });

  it("importData rejects non-integer rounds", async () => {
    const sls = secureLocalStorage({ storageKey: "test:import:rounds-float" });
    const bad = JSON.stringify({
      header: { v: 2, salt: "YWJj", rounds: 1.5, iv: "YWJj", wrappedKey: "YWJj" },
      data: { iv: "YWJj", ciphertext: "YWJj" }
    });
    await expect(sls.importData(bad, "x")).rejects.toBeInstanceOf(ImportError);
  });
});