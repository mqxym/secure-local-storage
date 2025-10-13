import { PersistedConfig, PersistedConfigV2, PersistedConfigV3 } from "../../types";
import { IdbConfig } from "../../crypto/DeviceKeyProvider";
import { EncryptionManager } from "../../crypto/EncryptionManager";
export declare class VersionManager {
    readonly storageKey: string;
    readonly idbConfig: IdbConfig;
    private readonly enc;
    constructor(storageKey: string, idbConfig: IdbConfig, enc: EncryptionManager);
    getAadFor(type: "wrap" | "data", config: PersistedConfig | null): Uint8Array | undefined;
    isV3(config: PersistedConfig): config is PersistedConfigV3;
    isV2(config: PersistedConfig): config is PersistedConfigV2;
    isValidConfig(config: PersistedConfig | null): config is PersistedConfig;
    buildWrapAad(ctx: "store" | "export", version: number): Uint8Array;
    buildDataAad(ctx: "store" | "export", version: number, ivWrap: string, wrappedKey: string): Uint8Array;
}
