import "./../setup";
import secureLocalStorage from "../../src";
import { ValidationError } from "../../src/errors";

describe("SecureLocalStorage.setData input validation", () => {
  it("rejects arrays and null", async () => {
    const sls = secureLocalStorage({ storageKey: "test:setData:invalid" });
    await expect(sls.setData([] as unknown as Record<string, unknown>)).rejects.toBeInstanceOf(ValidationError);
    await expect(sls.setData(null as unknown as Record<string, unknown>)).rejects.toBeInstanceOf(ValidationError);
  });
});