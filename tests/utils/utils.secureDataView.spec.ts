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

import { ValidationError } from "../../src/errors";

describe("SecureDataView - meta operation hardening", () => {
  it("blocks setPrototypeOf/preventExtensions on top-level and nested views", async () => {
    const sls = secureLocalStorage({ storageKey: "test:view:meta" });
    await sls.setData({ x: 1, nested: { y: 2 } });

    const view = await sls.getData<{ x: number; nested: { y: number } }>();

    expect(() => Object.setPrototypeOf(view, null)).toThrow(ValidationError);
    expect(() => Object.preventExtensions(view)).toThrow(ValidationError);

    // nested proxy is also protected
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const n: any = (view as any).nested;
    expect(() => Object.setPrototypeOf(n, null)).toThrow(ValidationError);
    expect(() => Object.preventExtensions(n)).toThrow(ValidationError);

    view.clear();
  });
});

describe("SecureDataView - nested proxy identity & access", () => {
  it("returns a stable proxy instance for the same nested object", async () => {
    const sls = secureLocalStorage({ storageKey: "test:view:identity" });
    await sls.setData({ nested: { a: 1 } });

    const view = await sls.getData<{ nested: { a: number } }>();
    const first = view.nested;
    const second = view.nested;
    expect(first).toBe(second);
    view.clear();
  });

  it("returns undefined for unknown symbol property access (before clear)", async () => {
    const sls = secureLocalStorage({ storageKey: "test:view:symbol" });
    await sls.setData({ a: 1 });

    const view = await sls.getData<{ a: number }>();
    const sym = Symbol("missing");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((view as any)[sym]).toBeUndefined();
    view.clear();
  });

  it("nested reads throw LockedError after clear()", async () => {
    const sls = secureLocalStorage({ storageKey: "test:view:nested:clear" });
    await sls.setData({ nested: { a: 1 } });

    const view = await sls.getData<{ nested: { a: number } }>();
    const nested = view.nested;
    view.clear();
    expect(() => nested.a).toThrow(LockedError);
  });

  it("'has' trap reports clear as present and reflects own keys before clear", async () => {
    const sls = secureLocalStorage({ storageKey: "test:view:has" });
    await sls.setData({ a: 1 });

    const view = await sls.getData<{ a: number }>();
    expect("clear" in view).toBe(true);
    expect("a" in view).toBe(true);
    expect("missing" in view).toBe(false);
    view.clear();
  });
});