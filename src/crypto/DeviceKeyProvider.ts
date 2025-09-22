import { SLS_CONSTANTS } from "../constants";
import { NotSupportedError } from "../errors";

/** Public shape for configuring where the device KEK is persisted. */
export interface IdbConfig {
  dbName: string;
  storeName: string;
  keyId: string;
}

/** Resolve partial config to concrete values using current defaults. */
function resolveIdbConfig(cfg?: Partial<IdbConfig>): IdbConfig {
  return {
    dbName: cfg?.dbName ?? SLS_CONSTANTS.IDB.DB_NAME,
    storeName: cfg?.storeName ?? SLS_CONSTANTS.IDB.STORE,
    keyId: cfg?.keyId ?? SLS_CONSTANTS.IDB.ID
  };
}

/** Build a stable in-memory identity per (dbName, storeName, keyId). */
function memKeyId(cfg: IdbConfig): string {
  return `${cfg.dbName}::${cfg.storeName}::${cfg.keyId}`;
}

/**
 * Persists a non-extractable AES-GCM KEK in IndexedDB (origin-bound).
 * Falls back to an in-memory key if IndexedDB is unavailable or rejects storing CryptoKey.
 *
 * Now supports per-instance configuration of the IndexedDB DB/store/key id via IdbConfig.
 * If you don't pass a config, it uses SLS_CONSTANTS.IDB defaults (fully backwards compatible).
 */
export class DeviceKeyProvider {
  // Keep one in-memory key per (dbName, storeName, keyId)
  private static memoryKeys = new Map<string, CryptoKey>();

  static async getKey(cfgIn?: Partial<IdbConfig>): Promise<CryptoKey> {
    const cfg = resolveIdbConfig(cfgIn);
    const mk = memKeyId(cfg);

    // Prefer in-memory identity within the current session.
    const existingMem = this.memoryKeys.get(mk);
    if (existingMem) return existingMem;

    // If IndexedDB not available, use memory fallback
    if (!globalThis.indexedDB) {
      const k = await this.generateKek();
      this.memoryKeys.set(mk, k);
      return k;
    }

    const db = await this.openDB(cfg).catch(() => null);
    try {
      if (!db) {
        const k = await this.generateKek();
        this.memoryKeys.set(mk, k);
        return k;
      }

      const existing: CryptoKey | undefined = await new Promise((resolve, reject) => {
        const tx = db.transaction(cfg.storeName, "readonly");
        const req = tx.objectStore(cfg.storeName).get(cfg.keyId);
        req.onsuccess = () => resolve((req.result?.key as CryptoKey) || undefined);
        req.onerror = () => reject(req.error);
      });

      if (existing) {
        this.memoryKeys.set(mk, existing);
        return existing;
      }

      // Nothing persisted -> generate and try to persist
      const key = await this.generateKek();

      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(cfg.storeName, "readwrite");
        const put = tx.objectStore(cfg.storeName).put({ id: cfg.keyId, key });
        put.onsuccess = () => resolve();
        put.onerror = () => reject(put.error);
      }).catch(() => {
        // Storing CryptoKey failed (e.g., structured clone not supported) -> ignore and fall back to memory
      });

      // Prefer in-memory identity within the session
      this.memoryKeys.set(mk, key);
      return key;
    } catch {
      // Any unexpected failure -> ensure we still return a usable key
      let k = this.memoryKeys.get(mk);
      if (!k) {
        k = await this.generateKek();
        this.memoryKeys.set(mk, k);
      }
      return k;
    } finally {
      if (db) db.close();
    }
  }

  static async rotateKey(cfgIn?: Partial<IdbConfig>): Promise<CryptoKey> {
    const cfg = resolveIdbConfig(cfgIn);
    const mk = memKeyId(cfg);

    const newKey = await this.generateKek();

    if (!globalThis.indexedDB) {
      this.memoryKeys.set(mk, newKey);
      return newKey;
    }

    const db = await this.openDB(cfg).catch(() => null);
    try {
      if (!db) {
        this.memoryKeys.set(mk, newKey);
        return newKey;
      }
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(cfg.storeName, "readwrite");
        const put = tx.objectStore(cfg.storeName).put({ id: cfg.keyId, key: newKey });
        put.onsuccess = () => resolve();
        put.onerror = () => reject(put.error);
      });
      // Keep identity stable within session
      this.memoryKeys.set(mk, newKey);
      return newKey;
    } catch {
      this.memoryKeys.set(mk, newKey);
      return newKey;
    } finally {
      if (db) db.close();
    }
  }

  /**
   * Remove persisted key material for this configuration and clear the in-memory copy.
   * For backward compatibility with the original implementation, this deletes the whole DB
   * (default DB name), which is fine when you use distinct dbName per tenant/config.
   * If you prefer surgical deletes, switch to opening the DB and deleting only the record.
   */
  static async deletePersistent(cfgIn?: Partial<IdbConfig>): Promise<void> {
    const cfg = resolveIdbConfig(cfgIn);
    const mk = memKeyId(cfg);
    this.memoryKeys.delete(mk);

    if (!globalThis.indexedDB) return;

    // Back-compat behavior: delete entire DB (as before)
    await new Promise<void>((resolve, reject) => {
      const req = indexedDB.deleteDatabase(cfg.dbName);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    }).catch(() => {
      // Swallow errors to match previous behavior
    });
  }

  // --------------------------- private helpers ---------------------------

  private static async generateKek(): Promise<CryptoKey> {
    return await crypto.subtle.generateKey(
      { name: SLS_CONSTANTS.AES.NAME, length: SLS_CONSTANTS.AES.LENGTH },
      false,
      ["wrapKey", "unwrapKey"]
    );
  }

  private static openDB(cfg: IdbConfig): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      try {
        const req = indexedDB.open(cfg.dbName, 1);
        req.onupgradeneeded = () => {
          if (!req.result.objectStoreNames.contains(cfg.storeName)) {
            req.result.createObjectStore(cfg.storeName, { keyPath: "id" });
          }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () =>
          reject(new NotSupportedError(req.error?.message ?? "IndexedDB error"));
      } catch (e) {
        reject(new NotSupportedError((e as Error)?.message ?? "IndexedDB unavailable"));
      }
    });
  }
}