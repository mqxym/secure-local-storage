import "./../setup";
import { safeParseJson, toPlainJson } from "../../src/utils/json";
import { ValidationError } from "../../src/errors";

describe("json utils", () => {
  it("toPlainJson rejects functions and circular structures", () => {
    expect(() => toPlainJson({ f: () => 1 } as unknown as Record<string, unknown>)).toThrow(ValidationError);
    const a: Record<string, unknown> = {};
    a.self = a;
    expect(() => toPlainJson(a)).toThrow(ValidationError);
  });

  it("safeParseJson throws on invalid input", () => {
    expect(() => safeParseJson("{}]")).toThrow(ValidationError);
  });
});


describe("json utils - extra serialization edge cases", () => {
  it("rejects BigInt via JSON serialization failure", () => {
    // eslint-disable-next-line @typescript-eslint/no-loss-of-precision
    const v = { big: BigInt(10) } as unknown as Record<string, unknown>;
    expect(() => toPlainJson(v)).toThrow(ValidationError);
  });

  it("drops top-level and nested undefined properties", () => {
    const out = toPlainJson({ a: 1, b: undefined, nested: { c: undefined, d: 2 } } as Record<string, unknown>);
    expect(out).toEqual({ a: 1, nested: { d: 2 } });
    expect(Object.prototype.hasOwnProperty.call(out, "b")).toBe(false);
  });

  it("coerces undefined array elements to null", () => {
    const out = toPlainJson({ list: [1, undefined, 3] } as unknown as Record<string, unknown>);
    expect(out).toEqual({ list: [1, null, 3] });
  });

  it("silently coerces Date to an ISO string", () => {
    const when = new Date("2026-06-30T00:00:00.000Z");
    const out = toPlainJson({ when } as unknown as Record<string, unknown>);
    expect(out.when).toBe("2026-06-30T00:00:00.000Z");
    expect(typeof out.when).toBe("string");
  });

  it("Map and Set lose their type and serialize to empty objects", () => {
    const out = toPlainJson({
      m: new Map([["k", "v"]]),
      s: new Set([1, 2, 3])
    } as unknown as Record<string, unknown>);
    expect(out).toEqual({ m: {}, s: {} });
  });

  it("returns an independent deep clone (mutating the source does not affect the result)", () => {
    const source = { nested: { value: 1 } };
    const out = toPlainJson(source);
    source.nested.value = 999;
    expect(out.nested.value).toBe(1);
    expect(out).not.toBe(source);
    expect(out.nested).not.toBe(source.nested);
  });

  it("rejects functions and symbols nested deep inside the structure", () => {
    expect(() =>
      toPlainJson({ a: { b: { c: () => 1 } } } as unknown as Record<string, unknown>)
    ).toThrow(ValidationError);
    expect(() =>
      toPlainJson({ a: { b: { c: Symbol("x") } } } as unknown as Record<string, unknown>)
    ).toThrow(ValidationError);
  });

  it("attaches the underlying error as cause when serialization fails", () => {
    let caught: unknown;
    try {
      toPlainJson({ big: BigInt(1) } as unknown as Record<string, unknown>);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ValidationError);
    expect((caught as ValidationError).cause).toBeInstanceOf(Error);
  });

  it("safeParseJson attaches the underlying parse error as cause", () => {
    let caught: unknown;
    try {
      safeParseJson("{not-json");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ValidationError);
    expect((caught as ValidationError).cause).toBeInstanceOf(Error);
  });
});