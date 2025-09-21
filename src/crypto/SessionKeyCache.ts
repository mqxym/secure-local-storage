/**
 * Caches a derived KEK (CryptoKey) for master password sessions.
 * Key is non-extractable and kept only in RAM.
 */
export class SessionKeyCache {
  private key: CryptoKey | null = null;
  private saltB64: string | null = null;
  private rounds: number | null = null;

  set(key: CryptoKey, saltB64: string, rounds: number) {
    this.key = key;
    this.saltB64 = saltB64;
    this.rounds = rounds;
  }

  match(saltB64: string, rounds: number): CryptoKey | null {
    if (!this.key) return null;
    if (this.saltB64 === saltB64 && this.rounds === rounds) return this.key;
    return null;
  }

  clear() {
    this.key = null;
    this.saltB64 = null;
    this.rounds = null;
  }
}