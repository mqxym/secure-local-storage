import "./../setup";
import secureLocalStorage from "../../src";
import { DeviceKeyProvider } from "../../src/crypto/DeviceKeyProvider";

describe("clear() respects idbConfig and removes the correct KEK namespace", () => {
  it("passes the instance idbConfig to DeviceKeyProvider.deletePersistent()", async () => {
    const idbConfig = { dbName: "DB_A", storeName: "STORE_A", keyId: "KEY_A" };
    const sls = secureLocalStorage({ storageKey: "test:clear:idb:A", idbConfig });
    await sls.setData({ v: 1 });

    const k1 = await DeviceKeyProvider.getKey(idbConfig);
    await sls.clear();
    const k2 = await DeviceKeyProvider.getKey(idbConfig);

    // After a proper clear, the in-memory entry for this id should be gone,
    // leading to a different CryptoKey object identity.
    expect(k1).not.toBe(k2);
  });
});