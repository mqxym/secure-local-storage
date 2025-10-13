export interface EncryptedBlob {
    iv: string;
    ciphertext: string;
}
export interface HeaderV2 {
    v: 2;
    salt: string;
    rounds: number;
    iv: string;
    wrappedKey: string;
    mPw?: boolean;
}
export interface HeaderV3 {
    v: 3;
    salt: string;
    rounds: number;
    iv: string;
    wrappedKey: string;
    mPw?: boolean;
    /**
     * AAD context:
     * - "store"  => persisted in localStorage (binds to storageKey)
     * - "export" => exported bundle (portable, not bound to storageKey)
     */
    ctx?: "store" | "export";
}
export interface PersistedConfigV2 {
    header: HeaderV2;
    data: EncryptedBlob;
}
export interface PersistedConfigV3 {
    header: HeaderV3;
    data: EncryptedBlob;
}
export type PersistedConfig = PersistedConfigV2 | PersistedConfigV3;
