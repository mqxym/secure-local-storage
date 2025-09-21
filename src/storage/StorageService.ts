import { SLS_CONSTANTS } from "../constants";
import { PersistedConfigV2 } from "../types";
import { StorageFullError } from "../errors";

function estimateBytes(s: string): number {
  // Blob accurately measures UTF-16->UTF-8 size in browsers
  try {
    return new Blob([s]).size;
  } catch {
    return s.length;
  }
}

export class StorageService {
  private key = SLS_CONSTANTS.STORAGE_KEY;

  get(): PersistedConfigV2 | null {
    const raw = localStorage.getItem(this.key);
    if (!raw) return null;
    try {
      return JSON.parse(raw) as PersistedConfigV2;
    } catch {
      // Corrupted data → treat as absent
      return null;
    }
  }

  set(cfg: PersistedConfigV2): void {
    const serialized = JSON.stringify(cfg);
    try {
      // Try to write; rely on UA to enforce quota
      localStorage.setItem(this.key, serialized);
      // Verify round-trip (detect silent failures)
      const check = localStorage.getItem(this.key);
      if (check !== serialized) {
        throw new StorageFullError("Failed to persist data (quota or storage policy)");
      }
    } catch (e) {
      // Certain browsers throw DOMException with name QuotaExceededError
      const msg = (e as Error)?.message ?? String(e);
      throw new StorageFullError(`localStorage quota exceeded or blocked (${estimateBytes(serialized)} bytes attempted): ${msg}`);
    }
  }

  clear(): void {
    try {
      localStorage.removeItem(this.key);
    } catch {
      // ignore
    }
  }
}