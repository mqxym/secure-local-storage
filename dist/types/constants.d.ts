export declare const SLS_CONSTANTS: {
    CURRENT_DATA_VERSION: 2;
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
