import "../setup";
import secureLocalStorage from "../../src";
import { ImportError } from "../../src/errors";

describe("importData validation edge cases", () => {
  it("rejects empty serialized payload", async () => {
    const sls = secureLocalStorage({ storageKey: "test:import:empty" });
    await expect(sls.importData("")).rejects.toBeInstanceOf(ImportError);
  });
});


describe("importData strict validation & messaging (additional)", () => {
  it("rejects partially populated data section (iv present, ciphertext empty)", async () => {
    const sls = secureLocalStorage({ storageKey: "test:import:strict:partial-data" });
    const bad = JSON.stringify({
      header: { v: 2, salt: "", rounds: 1, iv: "YWJj", wrappedKey: "YWJj" },
      data:   { iv: "YWJj", ciphertext: "" } // <-- illegal: must be both-or-none
    });
    await expect(sls.importData(bad, "x")).rejects.toBeInstanceOf(ImportError);
  });

  it("rejects header.rounds above allowed maximum", async () => {
    const sls = secureLocalStorage({ storageKey: "test:import:strict:rounds-high" });
    // rounds far above MAX_ITERATIONS (64)
    const bad = JSON.stringify({
      header: { v: 2, salt: "YWJj", rounds: 1000, iv: "YWJj", wrappedKey: "YWJj" },
      data:   { iv: "", ciphertext: "" }
    });
    await expect(sls.importData(bad, "x")).rejects.toBeInstanceOf(ImportError);
  });
});


describe("importData validation edge cases (size limit)", () => {
  it("rejects oversized payloads before parsing", async () => {
    const sls = secureLocalStorage({ storageKey: "test:import:too-large" });
    const tooLarge = "A".repeat(2 * 1024 * 1024 + 1); // > 2 MiB guard
    await expect(sls.importData(tooLarge, "x")).rejects.toBeInstanceOf(ImportError);
  });
});