import "../setup";
import { DeviceKeyProvider } from "../../src/crypto/DeviceKeyProvider";
import { SLS_CONSTANTS } from "../../src/constants";

function openDb(dbName: string, storeName: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(dbName, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(storeName)) {
        req.result.createObjectStore(storeName, { keyPath: "id" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

describe("DeviceKeyProvider - ignores malformed persisted records", () => {
  it("treats a non-CryptoKey record as missing and regenerates a valid KEK", async () => {
    const cfg = { dbName: "SLS_KEYS_MALFORMED", storeName: SLS_CONSTANTS.IDB.STORE, keyId: "deviceKek_v1_bad" };

    // Persist a malformed record
    const db = await openDb(cfg.dbName, cfg.storeName);
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(cfg.storeName, "readwrite");
      tx.objectStore(cfg.storeName).put({ id: cfg.keyId, key: "__not_a_crypto_key__" });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    db.close();

    const key = await DeviceKeyProvider.getKey(cfg);
    expect((key.algorithm as { name?: string }).name).toBe("AES-GCM");
    expect(key.usages).toEqual(expect.arrayContaining(["wrapKey", "unwrapKey"]));
  });
});