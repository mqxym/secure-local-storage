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
export interface PersistedConfigV2 {
    header: HeaderV2;
    data: EncryptedBlob;
}
