import { SLS_CONSTANTS } from "../constants";
import { NotSupportedError } from "../errors";

/**
 * Persists a non-extractable AES-GCM KEK in IndexedDB (origin-bound).
 * Falls back to an in-memory key if IndexedDB is unavailable or rejects storing CryptoKey.
 */
export class DeviceKeyProvider {
  private static memoryKey: CryptoKey | null = null;

  static async getKey(): Promise<CryptoKey> {
    // If IndexedDB not available, use memory fallback
    if (!("indexedDB" in globalThis)) {
      if (this.memoryKey) return this.memoryKey;
      this.memoryKey = await this.generateKek();
      return this.memoryKey;
    }

    const db = await this.openDB().catch(() => null);
    if (!db) {
      // fallback to memory
      if (this.memoryKey) return this.memoryKey;
      this.memoryKey = await this.generateKek();
      return this.memoryKey;
    }

    try {
      const existing: CryptoKey | undefined = await new Promise((resolve, reject) => {
        const tx = db.transaction(SLS_CONSTANTS.IDB.STORE, "readonly");
        const req = tx.objectStore(SLS_CONSTANTS.IDB.STORE).get(SLS_CONSTANTS.IDB.ID);
        req.onsuccess = () => resolve(req.result?.key as CryptoKey | undefined);
        req.onerror = () => reject(req.error);
      });
      if (existing) {
        db.close();
        return existing;
      }

      const key = await this.generateKek();

      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(SLS_CONSTANTS.IDB.STORE, "readwrite");
        const put = tx.objectStore(SLS_CONSTANTS.IDB.STORE).put({ id: SLS_CONSTANTS.IDB.ID, key });
        put.onsuccess = () => resolve();
        put.onerror = () => reject(put.error);
      }).catch(async () => {
        // storing CryptoKey failed (structured clone not supported) -> memory fallback
        this.memoryKey = key;
      });

      db.close();
      return this.memoryKey ?? key;
    } catch {
      db.close();
      // final fallback
      if (!this.memoryKey) this.memoryKey = await this.generateKek();
      return this.memoryKey;
    }
  }

  static async rotateKey(): Promise<CryptoKey> {
    const newKey = await this.generateKek();
    if (!("indexedDB" in globalThis)) {
      this.memoryKey = newKey;
      return newKey;
    }
    const db = await this.openDB().catch(() => null);
    if (!db) {
      this.memoryKey = newKey;
      return newKey;
    }
    try {
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(SLS_CONSTANTS.IDB.STORE, "readwrite");
        const put = tx.objectStore(SLS_CONSTANTS.IDB.STORE).put({ id: SLS_CONSTANTS.IDB.ID, key: newKey });
        put.onsuccess = () => resolve();
        put.onerror = () => reject(put.error);
      });
      db.close();
      return newKey;
    } catch {
      db.close();
      this.memoryKey = newKey;
      return newKey;
    }
  }

  static async deletePersistent(): Promise<void> {
    this.memoryKey = null;
    if (!("indexedDB" in globalThis)) return;
    await new Promise<void>((resolve, reject) => {
      const req = indexedDB.deleteDatabase(SLS_CONSTANTS.IDB.DB_NAME);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    }).catch(() => {});
  }

  private static async generateKek(): Promise<CryptoKey> {
    return await crypto.subtle.generateKey(
      { name: SLS_CONSTANTS.AES.NAME, length: SLS_CONSTANTS.AES.LENGTH },
      false,
      ["wrapKey", "unwrapKey"]
    );
  }

  private static openDB(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(SLS_CONSTANTS.IDB.DB_NAME, 1);
      req.onupgradeneeded = () => {
        req.result.createObjectStore(SLS_CONSTANTS.IDB.STORE, { keyPath: "id" });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(new NotSupportedError(req.error?.message ?? "IndexedDB error"));
    });
  }
}