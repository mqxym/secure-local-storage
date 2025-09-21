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

export interface PersistedConfigV2 {
  header: HeaderV2;
  data: EncryptedBlob; // encrypted user data
}