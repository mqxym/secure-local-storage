import { SLS_CONSTANTS } from "../constants";
import { NotSupportedError } from "../errors";

/**
 * Persists a non-extractable AES-GCM KEK in IndexedDB (origin-bound).
 * Falls back to an in-memory key if IndexedDB is unavailable or rejects storing CryptoKey.
 */
export class DeviceKeyProvider {
  private static memoryKey: CryptoKey | null = null;

  static async getKey(): Promise<CryptoKey> {
    // Always prefer an in-memory key within the current session.
    if (this.memoryKey) return this.memoryKey;

    // If IndexedDB not available, use memory fallback
    if (!globalThis.indexedDB) {
      this.memoryKey = await this.generateKek();
      return this.memoryKey;
    }

    const db = await this.openDB().catch(() => null);
    try {
      if (!db) {
        this.memoryKey = await this.generateKek();
        return this.memoryKey;
      }

      const existing: CryptoKey | undefined = await new Promise((resolve, reject) => {
        const tx = db.transaction(SLS_CONSTANTS.IDB.STORE, "readonly");
        const req = tx.objectStore(SLS_CONSTANTS.IDB.STORE).get(SLS_CONSTANTS.IDB.ID);
        req.onsuccess = () => resolve(req.result?.key as CryptoKey | undefined);
        req.onerror = () => reject(req.error);
      });

      if (existing) {
        this.memoryKey = existing;
        return this.memoryKey;
      }

      const key = await this.generateKek();

      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(SLS_CONSTANTS.IDB.STORE, "readwrite");
        const put = tx.objectStore(SLS_CONSTANTS.IDB.STORE).put({ id: SLS_CONSTANTS.IDB.ID, key });
        put.onsuccess = () => resolve();
        put.onerror = () => reject(put.error);
      }).catch(() => {
        // storing CryptoKey failed (structured clone not supported) -> memory fallback
      });

      // Prefer in-memory identity within the session
      this.memoryKey = key;
      return this.memoryKey;
    } catch {
      if (!this.memoryKey) this.memoryKey = await this.generateKek();
      return this.memoryKey;
    } finally {
      if (db) db.close();
    }
  }

  static async rotateKey(): Promise<CryptoKey> {
    const newKey = await this.generateKek();

    if (!("indexedDB" in globalThis)) {
      this.memoryKey = newKey;
      return newKey;
    }

    const db = await this.openDB().catch(() => null);
    try {
      if (!db) {
        this.memoryKey = newKey;
        return newKey;
      }
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(SLS_CONSTANTS.IDB.STORE, "readwrite");
        const put = tx.objectStore(SLS_CONSTANTS.IDB.STORE).put({ id: SLS_CONSTANTS.IDB.ID, key: newKey });
        put.onsuccess = () => resolve();
        put.onerror = () => reject(put.error);
      });
      this.memoryKey = newKey; // keep identity stable within session
      return newKey;
    } catch {
      this.memoryKey = newKey;
      return newKey;
    } finally {
      if (db) db.close();
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