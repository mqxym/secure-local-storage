/**
 * Caches a derived KEK (CryptoKey) for master password sessions.
 * Key is non-extractable and kept only in RAM.
 */
export declare class SessionKeyCache {
    private key;
    private saltB64;
    private rounds;
    set(key: CryptoKey, saltB64: string, rounds: number): void;
    match(saltB64: string, rounds: number): CryptoKey | null;
    clear(): void;
}
