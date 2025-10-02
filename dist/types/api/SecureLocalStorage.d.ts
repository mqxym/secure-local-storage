import { SecureDataView } from "../utils/secureDataView";
import type { IdbConfig } from "../crypto/DeviceKeyProvider";
/**
 * Configuration options for initializing SecureLocalStorage.
 */
export interface SecureLocalStorageOptions {
    /**
     * Overrides the default key used for storing encrypted data in `localStorage`.
     * This is useful for multi-tenant applications or for isolating data in tests.
     * @default "secure-local-storage"
     */
    storageKey?: string;
    /**
     * Overrides the default IndexedDB configuration for storing the device-specific key.
     * This is useful for multi-tenant applications or for isolating data in tests.
     */
    idbConfig?: Partial<IdbConfig>;
}
/**
 * Provides a secure, client-side storage solution that encrypts data before persisting it.
 *
 * `SecureLocalStorage` offers two primary modes of operation:
 * 1.  **Device-bound Mode**: (Default) Data is encrypted with a key that is stored in
 *     the browser's IndexedDB. This key is unique to the device and profile, making it
 *     difficult to access from other devices. Data is automatically unlocked when the
 *     class is instantiated.
 * 2.  **Master Password Mode**: Data is encrypted with a key derived from a user-provided
 *     master password. The data can only be accessed by providing the correct password,
 *     allowing for portability across devices but requiring user interaction to unlock.
 *
 * The class handles key management, encryption, and data serialization, providing a
 * simple `getData`/`setData` interface for application use. It also supports features
 * like key rotation, data export/import, and changing or removing the master password.
 *
 * @example
 * ```typescript
 * // Initialize in device-bound mode
 * const sls = new SecureLocalStorage();
 *
 * // Set some data
 * await sls.setData({ mySecret: "hello world" });
 *
 * // Get the data back
 * const dataView = await sls.getData();
 * console.log(dataView.value.mySecret); // "hello world"
 *
 * // Wipe the plaintext from memory
 * dataView.clear();
 * ```
 *
 * @example
 * ```typescript
 * // Initialize and set a master password
 * const sls = new SecureLocalStorage();
 * await sls.setMasterPassword("my-strong-password-123");
 *
 * // Later, in a new session
 * const sls2 = new SecureLocalStorage();
 * await sls2.unlock("my-strong-password-123");
 * const data = await sls2.getData();
 * // ... use data
 * sls2.lock(); // clear session keys
 * ```
 */
export declare class SecureLocalStorage {
    private readonly store;
    private readonly enc;
    private readonly session;
    private config;
    private dek;
    private ready;
    private readonly idbConfig;
    /**
     * The current version of the data structure format.
     */
    readonly DATA_VERSION: number;
    /**
     * Initializes a new instance of SecureLocalStorage.
     *
     * The constructor immediately begins an asynchronous initialization process.
     * Public methods will await this process, so you don't need to manually wait
     * for it to complete.
     *
     * @param opts - Optional configuration to customize storage keys.
     */
    constructor(opts?: SecureLocalStorageOptions);
    /**
     * Checks if the storage is currently protected by a master password.
     * @returns `true` if a master password is set, `false` otherwise.
     */
    isUsingMasterPassword(): boolean;
    /**
     * Checks if the storage is currently locked.
     * This is only relevant when in master password mode.
     * @returns `true` if in master password mode and no dek or session, otherwise `false`.
     */
    isLocked(): boolean;
    /**
     * Unlocks the data encryption key (DEK) using the provided master password.
     * This is required to access data when in master password mode.
     * If the store is in device-bound mode or is already unlocked, this method does nothing.
     *
     * @param masterPassword - The user's master password.
     * @throws {ValidationError} If the master password is an empty string or invalid.
     */
    unlock(masterPassword: string): Promise<void>;
    /**
     * Sets a master password, switching from device-bound mode to master password mode.
     * This re-encrypts the data encryption key (DEK) with a new key derived from the password.
     *
     * @param masterPassword - The new master password to set. Must be a non-empty string.
     * @throws {ModeError} If a master password is already set.
     * @throws {ValidationError} If the master password is an empty string.
     */
    setMasterPassword(masterPassword: string): Promise<void>;
    /**
     * Removes the master password, switching back to device-bound mode.
     * The DEK is re-encrypted using the device-specific key.
     * Requires the session to be unlocked.
     *
     * @throws {ModeError} If no master password is set.
     * @throws {LockedError} If the session is locked.
     */
    removeMasterPassword(): Promise<void>;
    /**
     * Atomically changes the master password.
     * If not in master password mode, it will set the new password.
     *
     * @param oldMasterPassword - The current master password.
     * @param newMasterPassword - The new master password. Must be a non-empty string.
     * @throws {ValidationError} If the new password is empty or if the old password is incorrect.
     * @throws {LockedError} If the session is locked.
     */
    rotateMasterPassword(oldMasterPassword: string, newMasterPassword: string): Promise<void>;
    /**
     * Locks the session by clearing the cached Key Encryption Key (KEK) and
     * Data Encryption Key (DEK) from memory.
     * After locking, `unlock()` must be called to perform further operations.
     */
    lock(): void;
    /**
     * Rotates the Data Encryption Key (DEK) and the device-specific Key Encryption Key (KEK).
     * This enhances security by replacing the keys used to protect the data.
     * This operation is only allowed in device-bound mode.
     *
     * @throws {ModeError} If a master password is set.
     */
    rotateKeys(): Promise<void>;
    /**
     * Retrieves the decrypted data.
     *
     * @returns A promise that resolves to a `SecureDataView`, a wrapper around the
     *          decrypted data object that includes a `wipe()` method to securely
     *          clear the plaintext data from memory.
     * @throws {LockedError} If the session is locked.
     * @throws {ValidationError} If the stored data is not a plain object.
     * @template T The expected type of the stored data object.
     */
    getData<T extends Record<string, unknown> = Record<string, unknown>>(): Promise<SecureDataView<T>>;
    /**
     * Encrypts and persists the provided data object, replacing any existing data.
     *
     * @param value The plain JavaScript object to store. It must be serializable.
     * @throws {LockedError} If the session is locked.
     * @throws {ValidationError} If the provided value is not a plain object.
     */
    setData<T extends Record<string, unknown>>(value: T): Promise<void>;
    /**
     * Exports the encrypted data bundle as a JSON string.
     *
     * There are two export modes:
     * 1.  **Master Password Mode**: If no `customExportPassword` is provided and a master
     *     password is set, the bundle is exported using the existing master password.
     * 2.  **Custom Password Mode**: If a `customExportPassword` is provided, the bundle
     *     is re-encrypted with a key derived from this password. This is required when
     *     in device-bound mode.
     *
     * @param customExportPassword - An optional password to protect the exported data.
     *        Required if not in master password mode.
     * @returns A JSON string representing the encrypted data bundle.
     * @throws {ExportError} If a password is required but not provided, or if the
     *         provided password is invalid.
     */
    exportData(customExportPassword?: string): Promise<string>;
    /**
     * Imports a previously exported data bundle.
     *
     * The method determines whether to use a master password or an export password
     * based on the bundle's metadata. After a successful import using an export
     * password, the data is re-encrypted into device-bound mode. If imported with a
     * master password, it remains in master password mode.
     *
     * @param serialized - The JSON string of the exported data bundle.
     * @param password - The password required to decrypt the bundle (master or export).
     * @returns A promise that resolves to 'masterPassword' or 'customExportPassword'
     *          indicating which type of password was used for the import.
     * @throws {ImportError} If the JSON is invalid, the bundle is corrupted, the
     *         password is required but missing, or the password is incorrect.
     */
    importData(serialized: string, password?: string): Promise<string>;
    /**
     * Clears all stored data, including the encrypted bundle from `localStorage` and
     * the device key from `IndexedDB`.
     * After clearing, the instance is reinitialized to a fresh, empty state in
     * device-bound mode.
     */
    clear(): Promise<void>;
    private initialize;
    private persist;
    private requireConfig;
    private requireUnlocked;
    private sessionKekOrThrow;
    private ensureDekLoaded;
    private unwrapDekWithKek;
    private validateBundle;
}
