import type { PersistedConfig } from "../../types";
import { EncryptionManager } from "../../crypto/EncryptionManager";
import { VersionManager } from "./VersionManager";
export type ExportSpec = {
    dek: CryptoKey;
    kek: CryptoKey;
    saltB64: string;
    rounds: number;
    mPw: boolean;
};
export declare const Portability: {
    buildExportBundle: (enc: EncryptionManager, versionManager: VersionManager, spec: ExportSpec, plainDataObj: unknown) => Promise<string>;
    parseAndClassify: (json: string, supported: readonly (2 | 3)[]) => {
        bundle: PersistedConfig;
        isMasterProtected: boolean;
    };
};
