import "../setup";
import { SessionKeyCache } from "../../src/crypto/SessionKeyCache";

describe("SessionKeyCache", () => {
  it("returns cached key only when salt & rounds match; clears correctly", async () => {
    const cache = new SessionKeyCache();
    const key = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"]
    );
    cache.set(key, "salt-1", 10);

    expect(cache.match("salt-1", 10)).toBe(key);
    expect(cache.match("salt-1", 9)).toBeNull();
    expect(cache.match("salt-2", 10)).toBeNull();

    cache.clear();
    expect(cache.match("salt-1", 10)).toBeNull();
  });
});