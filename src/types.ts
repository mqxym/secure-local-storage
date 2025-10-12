export interface EncryptedBlob {
  iv: string;          // base64
  ciphertext: string;  // base64
}

export interface HeaderV2 {
  v: 2;
  salt: string;        // base64 salt ("" for device mode)
  rounds: number;      // 1 for device mode; >1 for master
  iv: string;          // base64 (wrap IV)
  wrappedKey: string;  // base64 (wrapped DEK)
  // optional export marker when exporting with custom password
  mPw?: boolean;       // false => export password used; true => master password
}

export interface HeaderV3 {
  v: 3;
  salt: string;        // base64 salt ("" for device mode)
  rounds: number;      // 1 for device mode; >1 for master
  iv: string;          // base64 (wrap IV)
  wrappedKey: string;  // base64 (wrapped DEK)
  mPw?: boolean;       // optional, same semantics as v2 for exports
  /**
   * AAD context:
   * - "store"  => persisted in localStorage (binds to storageKey)
   * - "export" => exported bundle (portable, not bound to storageKey)
   */
  ctx?: "store" | "export";
}

export interface PersistedConfigV2 {
  header: HeaderV2;
  data: EncryptedBlob; // encrypted user data
}

export interface PersistedConfigV3 {
  header: HeaderV3;
  data: EncryptedBlob;
}

export type PersistedConfig = PersistedConfigV2 | PersistedConfigV3;