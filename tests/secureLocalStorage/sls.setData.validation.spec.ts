import "./../setup";
import secureLocalStorage from "../../src";
import { ValidationError } from "../../src/errors";

describe("SecureLocalStorage.setData input validation", () => {
  it("rejects arrays and null", async () => {
    const sls = secureLocalStorage({ storageKey: "test:setData:invalid" });
    await expect(sls.setData([] as unknown as Record<string, unknown>)).rejects.toBeInstanceOf(ValidationError);
    await expect(sls.setData(null as unknown as Record<string, unknown>)).rejects.toBeInstanceOf(ValidationError);
  });

  it("rejects primitive values (string, number, boolean, undefined)", async () => {
    const sls = secureLocalStorage({ storageKey: "test:setData:primitives" });
    await expect(sls.setData("hi" as unknown as Record<string, unknown>)).rejects.toBeInstanceOf(ValidationError);
    await expect(sls.setData(42 as unknown as Record<string, unknown>)).rejects.toBeInstanceOf(ValidationError);
    await expect(sls.setData(0 as unknown as Record<string, unknown>)).rejects.toBeInstanceOf(ValidationError);
    await expect(sls.setData(true as unknown as Record<string, unknown>)).rejects.toBeInstanceOf(ValidationError);
    await expect(sls.setData(undefined as unknown as Record<string, unknown>)).rejects.toBeInstanceOf(ValidationError);
  });

  it("accepts an empty plain object", async () => {
    const sls = secureLocalStorage({ storageKey: "test:setData:empty" });
    await sls.setData({});
    const view = await sls.getData<Record<string, unknown>>();
    expect(Object.keys(view).filter((k) => k !== "clear")).toEqual([]);
    view.clear();
  });
});