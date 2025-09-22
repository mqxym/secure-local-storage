import "./setup";
import { safeParseJson, toPlainJson } from "../src/utils/json";
import { ValidationError } from "../src/errors";

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