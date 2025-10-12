import "./../setup";
import secureLocalStorage from "../../src";
import { LockedError } from "../../src/errors";

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

import "../setup";

describe("SecureDataView - descriptor details", () => {
  it("clear is enumerable and descriptors reflect read-only semantics", async () => {
    const sls = secureLocalStorage({ storageKey: "test:view:desc" });
    await sls.setData({ a: 1 });

    const view = await sls.getData<{ a: number }>();
    const descClear = Object.getOwnPropertyDescriptor(view, "clear");
    expect(descClear?.enumerable).toBe(true);
    expect(descClear?.writable).toBe(false);

    // defineProperty should not be allowed
    expect(() => Object.defineProperty(view, "a", { value: 2 })).toThrow();

    view.clear();
    expect(() => Object.getOwnPropertyDescriptor(view, "a")).toThrow(LockedError);
  });
});