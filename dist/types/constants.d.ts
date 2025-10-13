export declare const SLS_CONSTANTS: {
    CURRENT_DATA_VERSION: 2;
    MIGRATION_TARGET_VERSION: 3;
    SUPPORTED_VERSIONS: readonly [2, 3];
    AES: {
        NAME: "AES-GCM";
        LENGTH: 256;
        IV_LENGTH: 12;
    };
    ARGON2: {
        TYPE: "id";
        ITERATIONS: number;
        MEMORY_KIB: number;
        PARALLELISM: number;
        MAX_ITERATIONS: 64;
        HASH_LEN: number;
    };
    STORAGE_KEY: string;
    IDB: {
        DB_NAME: string;
        STORE: string;
        ID: string;
    };
    SALT_LEN: number;
};
