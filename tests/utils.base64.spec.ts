import "./setup";
import { base64ToBytes, bytesToBase64 } from "../src/utils/base64";

describe("base64 utils", () => {
  it("round-trips bytes correctly", () => {
    const bytes = new Uint8Array([0, 1, 2, 253, 254, 255]);
    const b64 = bytesToBase64(bytes);
    const back = base64ToBytes(b64);
    expect(Array.from(back)).toEqual(Array.from(bytes));
  });
});