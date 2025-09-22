import "./setup";
import secureLocalStorage from "../src";
import { LockedError } from "../src/errors";

describe("SecureDataView edge cases", () => {
  it("enumeration and has-trap behavior before and after clear()", async () => {
    const sls = secureLocalStorage({ storageKey: "test:view:1" });
    await sls.setData({ a: 1, nested: { b: 2 } });

    const view = await sls.getData<{ a: number; nested: { b: number } }>();
    expect("a" in view).toBe(true);
    const keysBefore = Object.keys(view);
    expect(keysBefore).toEqual(expect.arrayContaining(["a", "nested", "clear"]));
    expect(keysBefore.includes("clear")).toBe(true);

    view.clear();

    // "clear" remains accessible
    expect("clear" in view).toBe(true);
    // Introspection throws once cleared
    expect(() => Object.keys(view)).toThrow(LockedError);
    expect(() => ("a" in view)).toThrow(LockedError);
  });
});