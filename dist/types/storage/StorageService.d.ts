import { type PersistedConfig } from "../types";
export declare class StorageService {
    private key;
    constructor(key?: string);
    get(): PersistedConfig | null;
    _isQuotaExceeded(err: unknown): boolean;
    set(cfg: PersistedConfig): void;
    clear(): void;
}
