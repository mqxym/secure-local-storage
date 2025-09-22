import { PersistedConfigV2 } from "../types";
export declare class StorageService {
    private key;
    constructor(key?: string);
    get(): PersistedConfigV2 | null;
    _isQuotaExceeded(err: unknown): boolean;
    set(cfg: PersistedConfigV2): void;
    clear(): void;
}
