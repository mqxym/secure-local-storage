import "../setup";
import { base64ToBytes, bytesToBase64 } from "../../src/utils/base64";
import { ValidationError } from "../../src/errors";

describe("base64 utils - additional edges", () => {
  it("bytesToBase64 handles empty input", () => {
    const out = bytesToBase64(new Uint8Array([]));
    expect(out).toBe("");
  });

  it("base64ToBytes rejects whitespace-only strings", () => {
    expect(() => base64ToBytes("   \n\t  ")).toThrow(ValidationError);
  });

  it("base64ToBytes tolerates embedded whitespace by normalizing", () => {
    const b = new Uint8Array([1, 2, 3, 4]);
    const b64 = bytesToBase64(b);
    const spaced = `  ${b64.slice(0, 2)} \n ${b64.slice(2)} `;
    const back = base64ToBytes(spaced);
    expect(Array.from(back)).toEqual(Array.from(b));
  });
});

describe("base64 size guard", () => {
  it("rejects base64 strings longer than the configured limit", () => {
    const tooLong = "A".repeat(1024 * 1024 + 1); // > MAX_BASE64_LEN (1 MiB)
    expect(() => base64ToBytes(tooLong)).toThrow(ValidationError);
  });
});

describe("base64 utils - input type & shape guards", () => {
  it("rejects non-string input", () => {
    expect(() => base64ToBytes(123 as unknown as string)).toThrow(ValidationError);
    expect(() => base64ToBytes(null as unknown as string)).toThrow(ValidationError);
    expect(() => base64ToBytes(undefined as unknown as string)).toThrow(ValidationError);
  });

  it("rejects strings whose length mod 4 === 1 (never valid base64)", () => {
    expect(() => base64ToBytes("AAAAA")).toThrow(ValidationError); // 5 chars
  });

  it("rejects strings containing invalid characters", () => {
    expect(() => base64ToBytes("****")).toThrow(ValidationError);
  });

  it("bytesToBase64 accepts an ArrayBuffer directly", () => {
    const u8 = new Uint8Array([1, 2, 3, 4]);
    const fromBuffer = bytesToBase64(u8.buffer);
    const fromView = bytesToBase64(u8);
    expect(fromBuffer).toBe(fromView);
    expect(Array.from(base64ToBytes(fromBuffer))).toEqual([1, 2, 3, 4]);
  });

  it("bytesToBase64 returns empty string for an empty ArrayBuffer", () => {
    expect(bytesToBase64(new ArrayBuffer(0))).toBe("");
  });
});