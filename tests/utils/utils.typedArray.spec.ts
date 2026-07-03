import "./../setup";
import { asArrayBuffer } from "../../src/utils/typedArray";

describe("typedArray utils - asArrayBuffer", () => {
  it("returns the underlying buffer when the view spans the whole buffer", () => {
    const u8 = new Uint8Array([1, 2, 3, 4]);
    const out = asArrayBuffer(u8);
    expect(out).toBe(u8.buffer);
    expect(Array.from(new Uint8Array(out))).toEqual([1, 2, 3, 4]);
  });

  it("returns a copy (not the original buffer) for a subarray with a byteOffset", () => {
    const base = new Uint8Array([10, 20, 30, 40, 50, 60]);
    const view = base.subarray(2, 5); // byteOffset = 2, length = 3
    expect(view.byteOffset).toBe(2);

    const out = asArrayBuffer(view);
    expect(out).not.toBe(base.buffer);
    expect(out.byteLength).toBe(3);
    expect(Array.from(new Uint8Array(out))).toEqual([30, 40, 50]);
  });

  it("returns a copy for a view shorter than its backing buffer", () => {
    const base = new Uint8Array([1, 2, 3, 4]);
    const view = new Uint8Array(base.buffer, 0, 2); // byteOffset 0 but shorter than buffer

    const out = asArrayBuffer(view);
    expect(out).not.toBe(base.buffer);
    expect(out.byteLength).toBe(2);
    expect(Array.from(new Uint8Array(out))).toEqual([1, 2]);
  });

  it("does not alias: mutating the copy leaves the source untouched", () => {
    const base = new Uint8Array([5, 6, 7, 8]);
    const view = base.subarray(1, 3); // copy path
    const out = asArrayBuffer(view);

    new Uint8Array(out)[0] = 99;
    expect(Array.from(base)).toEqual([5, 6, 7, 8]);
  });
});
