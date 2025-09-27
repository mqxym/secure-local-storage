import "../setup";
import secureLocalStorage from "../../src";
import { ImportError } from "../../src/errors";

describe("importData validation edge cases", () => {
  it("rejects empty serialized payload", async () => {
    const sls = secureLocalStorage({ storageKey: "test:import:empty" });
    await expect(sls.importData("")).rejects.toBeInstanceOf(ImportError);
  });
});