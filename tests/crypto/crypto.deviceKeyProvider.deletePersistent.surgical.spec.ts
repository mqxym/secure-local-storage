import "../setup";
import { DeviceKeyProvider } from "../../src/crypto/DeviceKeyProvider";

function openDb(dbName: string, storeName: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(dbName, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(storeName)) {
        req.result.createObjectStore(storeName, { keyPath: "id" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror  = () => reject(req.error);
  });
}

async function getRecord(db: IDBDatabase, storeName: string, id: string): Promise<unknown> {
  return await new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readonly");
    const g = tx.objectStore(storeName).get(id);
    g.onsuccess = () => resolve(g.result);
    g.onerror = () => reject(g.error);
  });
}

describe("DeviceKeyProvider.deletePersistent performs surgical deletes", () => {
  const shared = { dbName: "SLS_SHARED", storeName: "keys" } as const;

  it("deletes only the targeted keyId in a shared DB/store", async () => {
    const cfgA = { ...shared, keyId: "A" };
    const cfgB = { ...shared, keyId: "B" };

    // Pre-populate two records (we don't rely on CryptoKey cloneability)
    const db = await openDb(shared.dbName, shared.storeName);
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(shared.storeName, "readwrite");
      const os = tx.objectStore(shared.storeName);
      os.put({ id: "A", key: "placeholder-A" });
      os.put({ id: "B", key: "placeholder-B" });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    db.close();

    // Surgical delete A
    await DeviceKeyProvider.deletePersistent(cfgA);

    const db2 = await openDb(shared.dbName, shared.storeName);
    const recA = await getRecord(db2, shared.storeName, "A");
    const recB = await getRecord(db2, shared.storeName, "B");
    db2.close();

    expect(recA).toBeUndefined();
    expect(recB).toBeDefined();
  });
});