export const SLS_CONSTANTS = {
  CURRENT_DATA_VERSION: 2 as const, // keep 2 for backward compat / tests
  MIGRATION_TARGET_VERSION: 3 as const,
  SUPPORTED_VERSIONS: [2, 3] as const,

  // AES-GCM
  AES: {
    NAME: "AES-GCM" as const,
    LENGTH: 256 as const,
    IV_LENGTH: 12 as const // 96-bit nonce
  },

  // Argon2 (argon2-browser uses KiB for mem)
  ARGON2: {
    TYPE: "id" as const, // Argon2id
    ITERATIONS: 20,
    MEMORY_KIB: 64 * 1024,
    PARALLELISM: 1,
    MAX_ITERATIONS: 64 as const,
    HASH_LEN: 32 // 256-bit
  },

  // Storage
  STORAGE_KEY: "secure-local-storage",

  // IndexedDB
  IDB: {
    DB_NAME: "SLS_KEYS",
    STORE: "keys",
    ID: "deviceKek_v1"
  },

  // Salt for Argon2
  SALT_LEN: 16
};