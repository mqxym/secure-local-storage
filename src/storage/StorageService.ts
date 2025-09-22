import { SLS_CONSTANTS } from "../constants";
import { PersistedConfigV2 } from "../types";
import { StorageFullError } from "../errors";

function estimateBytes(s: string): number {
  try { return new Blob([s]).size; } catch { return s.length; }
}

export class StorageService {
  private key: string;

  constructor(key: string = SLS_CONSTANTS.STORAGE_KEY) {
    this.key = key;
  }

  get(): PersistedConfigV2 | null {
    const raw = localStorage.getItem(this.key);
    if (!raw) return null;
    try { return JSON.parse(raw) as PersistedConfigV2; } catch { return null; }
  }

  set(cfg: PersistedConfigV2): void {
    const serialized = JSON.stringify(cfg);
    try {
      localStorage.setItem(this.key, serialized);
      const check = localStorage.getItem(this.key);
      if (check !== serialized) throw new StorageFullError("Failed to persist data");
    } catch (e) {
      const msg = (e as Error)?.message ?? String(e);
      const name = (e as { name?: string })?.name ?? "";
      if (name === "QuotaExceededError") {
        throw new StorageFullError(`localStorage quota exceeded (${estimateBytes(serialized)} bytes)`);
      }
      throw new StorageFullError(`Failed to persist data: ${msg}`);
    } 
  }

  clear(): void {
    try { localStorage.removeItem(this.key); } catch { /* ignore */ }
  }
}