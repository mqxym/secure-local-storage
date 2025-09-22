import "./../setup";
import secureLocalStorage from "../../src";
import { LockedError, ValidationError } from "../../src/errors";

describe("SecureDataView deep immutability", () => {

  it("nested mutations throw ValidationError", async () => {
    const sls = secureLocalStorage({ storageKey: "test:view:deep:future" });
    await sls.setData({ a: 1, nested: { b: 2 } });
    const view = await sls.getData<{ a: number; nested: { b: number } }>();
    expect(() => { /* eslint-disable @typescript-eslint/no-explicit-any */
      (view as any).nested.b = 5;
    }).toThrow(ValidationError);
    view.clear();
  });

  it("once cleared, any introspection throws LockedError (existing contract)", async () => {
    const sls = secureLocalStorage({ storageKey: "test:view:deep:locked" });
    await sls.setData({ x: 1 });
    const view = await sls.getData<{ x: number }>();
    view.clear();
    expect(() => Object.keys(view)).toThrow(LockedError);
    expect(() => ("x" in view)).toThrow(LockedError);
  });
});