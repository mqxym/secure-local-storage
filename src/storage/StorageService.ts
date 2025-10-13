import { SLS_CONSTANTS } from "../constants";
import { type PersistedConfig } from "../types";
import { StorageFullError, PersistenceError } from "../errors";

function estimateBytes(s: string): number {
  try { return new Blob([s]).size; } catch { return s.length; }
}

export class StorageService {
  private key: string;

  constructor(key: string = SLS_CONSTANTS.STORAGE_KEY) {
    this.key = key;
  }

  get(): PersistedConfig | null {
    const raw = localStorage.getItem(this.key);
    if (!raw) return null;
    try { return JSON.parse(raw) as PersistedConfig; } catch { return null; }
  }

  _isQuotaExceeded(err: unknown): boolean {
    const e = err as { name?: string; code?: number; message?: string };
    const name = e?.name ?? "";
    const msg = e?.message ?? "";
    const code = e?.code;

    return (
      name === "QuotaExceededError" ||
      name === "NS_ERROR_DOM_QUOTA_REACHED" ||
      code === 22 ||            // legacy Safari / WebKit
      code === 1014 ||          // Firefox DOMException
      /quota/i.test(msg)        // generic safety net
    );
  }

  set(cfg: PersistedConfig): void {
    const serialized = JSON.stringify(cfg);
    try {
      localStorage.setItem(this.key, serialized);
      const check = localStorage.getItem(this.key);
      if (check !== serialized) {
        throw new PersistenceError("Failed to persist data (integrity check)");
      }
    } catch (e) {
      if (this._isQuotaExceeded(e)) {
        throw new StorageFullError(`localStorage quota exceeded (${estimateBytes(serialized)} bytes)`);
      }
      const msg = (e as Error)?.message ?? String(e);
      throw new PersistenceError(`Failed to persist data: ${msg}`);
    }
  }

  clear(): void {
    try { localStorage.removeItem(this.key); } catch { /* ignore */ }
  }
}