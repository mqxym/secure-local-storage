import "./../setup";
import { base64ToBytes, bytesToBase64 } from "../../src/utils/base64";

describe("base64 utils - URL-safe variant and validation", () => {
  it("accepts base64url (- and _) without padding after hardening", () => {
    const bytes = new Uint8Array([0, 1, 2, 253, 254, 255]);
    const std = bytesToBase64(bytes);
    const url = std.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    const back = base64ToBytes(url);
    expect(Array.from(back)).toEqual(Array.from(bytes));
  });
});