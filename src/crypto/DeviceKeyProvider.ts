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
  // Collision-free for arbitrary strings.
  return JSON.stringify([cfg.dbName, cfg.storeName, cfg.keyId]);
}

function isValidKek(candidate: unknown): candidate is CryptoKey {
  const key = candidate as CryptoKey | undefined;
  const algoName = (key?.algorithm as { name?: unknown })?.name;
  const usages = (key?.usages ?? []) as KeyUsage[];
  return (
    !!key &&
    typeof algoName === "string" &&
    algoName === SLS_CONSTANTS.AES.NAME &&
    Array.isArray(usages) &&
    usages.includes("wrapKey") &&
    usages.includes("unwrapKey")
  );
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

  // NEW: single-flight per memKeyId to avoid concurrent double-generation
  private static inflight = new Map<string, Promise<CryptoKey>>();

  static async getKey(cfgIn?: Partial<IdbConfig>): Promise<CryptoKey> {
    const cfg = resolveIdbConfig(cfgIn);
    const mk = memKeyId(cfg);

    // Fast path: already cached in memory
    const cached = this.memoryKeys.get(mk);
    if (cached) return cached;

    // Single-flight: if someone else is already fetching/generating, await it
    const pending = this.inflight.get(mk);
    if (pending) return pending;

    const work = this.getKeyInternal(cfg, mk);
    this.inflight.set(mk, work);

    try {
      return await work;
    } finally {
      // Ensure we don't leak the promise if it rejects/throws
      this.inflight.delete(mk);
    }
  }

  private static async getKeyInternal(cfg: IdbConfig, mk: string): Promise<CryptoKey> {
    // Re-check memory in case something populated it between getKey() and now.
    const cached = this.memoryKeys.get(mk);
    if (cached) return cached;

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

      // Attempt to load persisted record
      const existing: unknown = await new Promise<unknown>((resolve, reject) => {
        const tx = db.transaction(cfg.storeName, "readonly");
        const req = tx.objectStore(cfg.storeName).get(cfg.keyId);
        req.onsuccess = () => resolve(req.result?.key);
        req.onerror = () => reject(req.error);
      });

      if (isValidKek(existing)) {
        this.memoryKeys.set(mk, existing);
        return existing;
      }

      // If the record exists but is malformed, try to delete it (best effort)
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(cfg.storeName, "readwrite");
        const del = tx.objectStore(cfg.storeName).delete(cfg.keyId);
        del.onsuccess = () => resolve();
        del.onerror = () => reject(del.error);
      }).catch(() => {
        /* non-fatal */
      });

      // Nothing usable persisted -> generate a new KEK and try to persist it
      const key = await this.generateKek();

      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(cfg.storeName, "readwrite");
        const put = tx.objectStore(cfg.storeName).put({ id: cfg.keyId, key });
        put.onsuccess = () => resolve();
        put.onerror = () => reject(put.error);
      }).catch(() => {
        // Storing CryptoKey may fail (structured clone not supported) -> ignore and fall back to memory
      });

      // Always provide stable identity within the session
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
    this.memoryKeys.delete(memKeyId(cfg));

    if (!globalThis.indexedDB) return;

    // Prefer surgical delete of only the targeted keyId.
    const db = await this.openDB(cfg).catch(() => null);
    if (db) {
      try {
        await new Promise<void>((resolve, reject) => {
          const tx = db.transaction(cfg.storeName, "readwrite");
          const del = tx.objectStore(cfg.storeName).delete(cfg.keyId);
          del.onsuccess = () => resolve();
          del.onerror = () => reject(del.error);
        });
        db.close();
        return;
      } catch {
        // fall through to full DB delete
        db.close();
      }
    }

    // Fallback: delete the whole DB 
    await new Promise<void>((resolve) => {
      const req = indexedDB.deleteDatabase(cfg.dbName);
      req.onsuccess = () => resolve();
      req.onerror = () => resolve(); 
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