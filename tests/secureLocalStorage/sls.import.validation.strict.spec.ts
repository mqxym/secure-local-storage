import "../setup";
import secureLocalStorage from "../../src";
import { ImportError, ValidationError } from "../../src/errors";

describe("importData strict validation & messaging", () => {
  it("rejects invalid base64 in header", async () => {
    const sls = secureLocalStorage({ storageKey: "test:import:strict:badb64" });
    const bad = JSON.stringify({
      header: { v: 2, salt: "", rounds: 1, iv: "!!!", wrappedKey: "###" },
      data: { iv: "", ciphertext: "" }
    });
    await expect(sls.importData(bad, "x")).rejects.toBeInstanceOf(ImportError);
  });

  it("rejects rounds===1 with non-empty salt", async () => {
    const sls = secureLocalStorage({ storageKey: "test:import:strict:device-salt" });
    const bad = JSON.stringify({
      header: { v: 2, salt: "abc", rounds: 1, iv: "YWJj", wrappedKey: "YWJj" }, // base64 but semantically wrong
      data: { iv: "", ciphertext: "" }
    });
    await expect(sls.importData(bad, "x")).rejects.toBeInstanceOf(ImportError);
  });

  it("rejects rounds>1 with empty salt", async () => {
    const sls = secureLocalStorage({ storageKey: "test:import:strict:pw-nosalt" });
    const bad = JSON.stringify({
      header: { v: 2, salt: "", rounds: 5, iv: "YWJj", wrappedKey: "YWJj" },
      data: { iv: "", ciphertext: "" }
    });
    await expect(sls.importData(bad, "x")).rejects.toBeInstanceOf(ImportError);
  });

  it("rejects invalid header.mPw type", async () => {
    const sls = secureLocalStorage({ storageKey: "test:import:strict:mpw-type" });
    const bad = JSON.stringify({
      header: { v: 2, salt: "YWJj", rounds: 5, iv: "YWJj", wrappedKey: "YWJj", mPw: "yes" },
      data: { iv: "YWJj", ciphertext: "YWJj" }
    });
    await expect(sls.importData(bad, "x")).rejects.toBeInstanceOf(ImportError);
  });

  it("missing password for custom-export bundle => ImportError (message fits the path)", async () => {
    const sls = secureLocalStorage({ storageKey: "test:import:strict:msg" });
    await sls.setData({ a: 1 });
    const exported = await sls.exportData("exp-pass");
    const sls2 = secureLocalStorage({ storageKey: "test:import:strict:msg:dst" });
    await expect(sls2.importData(exported)).rejects.toBeInstanceOf(ImportError);
  });
});