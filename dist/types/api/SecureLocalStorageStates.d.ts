/**
 * High-level stateful API for secure, local, key-wrapped storage.
 *
 * @packageDocumentation
 *
 * @remarks
 * - The storage operates in two modes:
 *   - **Device mode** (default): Data is protected by a device-bound KEK kept in IndexedDB (with in-memory fallback).
 *     Calls like {@link SecureLocalStorage.getData} and {@link SecureLocalStorage.setData} work immediately (not locked).
 *   - **Master-password mode**: Data is wrapped by a KEK derived from a user password. The store starts **locked**
 *     in a fresh session. You must call {@link SecureLocalStorage.unlock} with the correct password before reading/writing.
 *
 * - All persisted content is encrypted with a random DEK (AES-GCM 256). The DEK is wrapped by either the device KEK
 *   or the master-password KEK. AES-GCM AAD binds header and data to the storage key to prevent “mix & match”.
 *
 * - Error taxonomy:
 *   - {@link ValidationError} — bad inputs, wrong API usage, wrong mode (e.g., empty password, missing key usage).
 *   - {@link LockedError} — operation requires an unlocked session.
 *   - {@link StorageFullError} — localStorage quota exceeded on persist.
 *   - {@link PersistenceError} — integrity/write failures outside quota conditions.
 *   - {@link ImportError} / {@link ExportError} — invalid import/export bundles or missing passwords.
 *   - {@link CryptoError} — cryptographic failure (invalid key or corrupted ciphertext).
 *
 * - Concurrency: Instances are independent. When in device mode, {@link rotateKeys} rotates only this instance’s
 *   device KEK namespace (see {@link SecureLocalStorageOptions.idbConfig}).
 */
import { EncryptionManager } from "../crypto/EncryptionManager";
import { DeviceKeyProvider } from "../crypto/DeviceKeyProvider";
import { deriveKekFromPassword } from "../crypto/KeyDerivation";
import { SessionKeyCache } from "../crypto/SessionKeyCache";
import { StorageService } from "../storage/StorageService";
import type { PersistedConfig, PersistedConfigV2 } from "../types";
import { SecureDataView } from "../utils/secureDataView";
import type { IdbConfig } from "../crypto/DeviceKeyProvider";
import { VersionManager } from "./sls/VersionManager";
import { State } from "./states/BaseState";
/**
 * Configuration for {@link SecureLocalStorage}.
 */
export interface SecureLocalStorageOptions {
    /**
     * The localStorage key used to persist the encrypted bundle.
     *
     * @defaultValue `"secure-local-storage:v2"` (see {@link SLS_CONSTANTS.STORAGE_KEY})
     *
     * @remarks
     * This value is also included in AES-GCM AAD for v3 bundles, binding the ciphertext to a specific storage key
     * and preventing replay/mix-ups across different keys.
     */
    storageKey?: string;
    /**
     * Custom namespace for device KEK persistence in IndexedDB.
     *
     * @remarks
     * - Useful for **multi-tenant** or **test isolation** scenarios to avoid KEK collisions.
     * - When omitted, defaults to {@link SLS_CONSTANTS.IDB}.
     * - Shape matches {@link IdbConfig}: `{ dbName, storeName, keyId }`.
     */
    idbConfig?: Partial<IdbConfig>;
}
/**
 * Main entry point for secure, local key-wrapped storage.
 *
 * @remarks
 * ### Modes
 * - **Device mode** (default): unlocked by default; {@link getData} works without `unlock()`.
 * - **Master-password mode**: call {@link setMasterPassword} to enable; the session remains unlocked
 *   until you call {@link lock}. On a new instance/session, {@link isLocked} will be `true` until {@link unlock}.
 *
 * ### Data model
 * - `setData()` accepts a **plain object** only (no arrays, functions, symbols, circular refs).
 * - `getData()` returns a **read-only** {@link SecureDataView}: attempting to modify or introspect it after `.clear()` throws.
 * - Encryption uses AES-GCM with 96-bit nonces and AAD binding header/data to the storage key.
 *
 * ### Persistence & integrity
 * - The encrypted bundle is written to `localStorage`. A post-write readback verifies integrity.
 * - Quota errors bubble as {@link StorageFullError}.
 *
 * @example
 * // Device mode (default)
 * const sls = new SecureLocalStorage({ storageKey: "app:sls" });
 * await sls.setData({ secret: 123 });
 * const view = await sls.getData<{ secret: number }>();
 * console.log(view.secret); // 123
 * view.clear();
 *
 * @example
 * // Master-password flow
 * const sls = new SecureLocalStorage({ storageKey: "app:sls" });
 * await sls.setData({ note: "hi" });
 * await sls.setMasterPassword("correct horse battery staple"); // now using master password
 * sls.lock();
 * await sls.unlock("correct horse battery staple");
 * const v = await sls.getData<{ note: string }>();
 * v.clear();
 *
 * @example
 * // Export / Import
 * const src = new SecureLocalStorage({ storageKey: "src" });
 * await src.setData({ a: 1 });
 * const bundle = await src.exportData("export-pass"); // custom password; portable
 *
 * const dst = new SecureLocalStorage({ storageKey: "dst" });
 * await dst.importData(bundle, "export-pass"); // imported into device mode on dst
 */
export declare class SecureLocalStorage {
    /** @internal Backing state machine (Initial → DeviceMode|Locked → MasterPassword). */
    private state;
    /** @internal Local storage service for the serialized bundle. */
    readonly store: StorageService;
    /** @internal Crypto primitives (AES-GCM, wrap/unwrap, salt). */
    readonly enc: EncryptionManager;
    /**
     * Session cache for a derived master-password KEK (in RAM only).
     * @internal
     */
    readonly session: SessionKeyCache;
    /**
     * The currently loaded config header+data (v2/v3). `null` until initialization completes or a fresh store is created.
     * @internal
     */
    config: PersistedConfig | null;
    /**
     * The currently unwrapped DEK for the session, or `null` if locked or not yet loaded.
     * @internal
     */
    dek: CryptoKey | null;
    /** @internal Resolves after InitialState.initialize(). All public async methods await this barrier. */
    private ready;
    /**
     * Resolved IndexedDB namespace used for device KEK persistence.
     * @remarks
     * Propagated to {@link DeviceKeyProvider} calls, including surgical deletes and rotations.
     */
    readonly idbConfig: {
        dbName: string;
        storeName: string;
        keyId: string;
    };
    /**
     * The storage key string used for persistence and AAD binding (v3).
     * @see {@link SecureLocalStorageOptions.storageKey}
     */
    readonly storageKeyStr: string;
    /** @internal Version helper to build AAD and validate/migrate between v2 and v3. */
    readonly versionManager: VersionManager;
    /**
     * Last reason why a store was reset during initialization.
     * - `"invalid-config"` — persisted payload failed structural or base64 checks.
     * - `"device-kek-mismatch"` — unwrap with device KEK failed; store was reinitialized.
     *
     * @internal
     */
    lastResetReason: "invalid-config" | "device-kek-mismatch" | null;
    /** @internal Exposed for tests: current data version. */
    readonly DATA_VERSION: number;
    /** @internal Indirection for tests/mocking. */
    readonly deviceKeyProvider: typeof DeviceKeyProvider;
    /** @internal Indirection for tests/mocking. */
    readonly deriveKekFromPassword: typeof deriveKekFromPassword;
    /**
     * Create a new SecureLocalStorage instance.
     *
     * @param opts - Optional configuration for storage key and KEK persistence namespace.
     *
     * @remarks
     * Construction kicks off async initialization. Public async methods await the internal `ready` barrier to ensure
     * the store is ready before operating.
     */
    constructor(opts?: SecureLocalStorageOptions);
    /** @internal State transition helper (do not call directly). */
    transitionTo(state: State): void;
    /**
     * Returns `true` if the store is protected by a master password.
     *
     * @returns Whether master-password mode is active.
     *
     * @remarks
     * - In device mode this is `false`.
     * - In master-password mode, a fresh instance in a new session will also be {@link isLocked locked} until {@link unlock}.
     */
    isUsingMasterPassword(): boolean;
    /**
     * Returns `true` if the session is locked (master-password mode and password not yet provided).
     *
     * @returns `true` when in master-password mode and locked; otherwise `false`.
     *
     * @remarks
     * - Device mode is never locked.
     * - After calling {@link lock}, this becomes `true` until {@link unlock}.
     */
    isLocked(): boolean;
    /**
     * Unlock a master-password protected store for this session.
     *
     * @param masterPassword - The correct master password (non-empty string).
     * @throws {@link ValidationError} If password is empty/whitespace.
     * @throws {@link ValidationError} If the password is incorrect.
     *
     * @remarks
     * - No-op in device mode.
     * - On success, the derived KEK is cached in RAM only (not persisted) for the current session.
     */
    unlock(masterPassword: string): Promise<void>;
    /**
     * Switch from device mode to master-password mode.
     *
     * @param masterPassword - New master password; must be non-empty after trimming.
     * @throws {@link ValidationError} If password is empty/whitespace.
     * @throws {@link ModeError} If already using a master password.
     *
     * @remarks
     * - Rewraps the DEK under a derived KEK (Argon2id), persists a v3 header, and keeps the session **unlocked**.
     */
    setMasterPassword(masterPassword: string): Promise<void>;
    /**
     * Remove master-password protection and return to device mode.
     *
     * @throws {@link LockedError} If called while locked.
     * @throws {@link ModeError} If no master password is set (i.e., already in device mode).
     *
     * @remarks
     * Rewraps the DEK under the device KEK; the session remains unlocked in device mode.
     */
    removeMasterPassword(): Promise<void>;
    /**
     * Rotate the master password while preserving data.
     *
     * @param oldMasterPassword - The current master password.
     * @param newMasterPassword - The new master password (non-empty after trimming).
     * @throws {@link ValidationError} If the old password is wrong or the new password is empty.
     *
     * @remarks
     * Verifies the old password against the stored header using AAD, then rewraps the DEK with a KEK derived from the new password.
     */
    rotateMasterPassword(oldMasterPassword: string, newMasterPassword: string): Promise<void>;
    /**
     * Lock the current session (master-password mode only).
     *
     * @remarks
     * - Clears the in-RAM derived KEK and DEK; persisted data remains intact.
     * - Device mode ignores `lock()` (no effect).
     */
    lock(): void;
    /**
     * Rotate the **device KEK** (device mode only) while preserving data.
     *
     * @throws {@link ModeError} If called in master-password mode.
     * @throws {@link PersistenceError} / {@link StorageFullError} On persist failures.
     *
     * @remarks
     * - Generates a new DEK and KEK, re-encrypts data, and persists a fresh header and ciphertext.
     * - Useful for recovering from suspected device KEK compromise or to force a fresh transient KEK.
     */
    rotateKeys(): Promise<void>;
    /**
     * Decrypt and return the current data as a read-only {@link SecureDataView}.
     *
     * @typeParam T - Shape of the stored object. Defaults to `Record<string, unknown>`.
     * @returns A secure, immutable view with a `.clear()` method to wipe the decrypted snapshot from memory.
     * @throws {@link LockedError} If called while locked (master-password mode).
     * @throws {@link ValidationError} If stored payload is not a plain object (tampering or contract violation).
     * @throws {@link CryptoError} If decryption fails (invalid key or corrupted data).
     *
     * @remarks
     * - In device mode, if `data.iv`/`ciphertext` are empty, an empty object view is returned.
     * - After calling `view.clear()`, any property access or meta-operation on the view throws {@link LockedError}.
     */
    getData<T extends Record<string, unknown> = Record<string, unknown>>(): Promise<SecureDataView<T>>;
    /**
     * Encrypt and persist a new object value.
     *
     * @typeParam T - Shape of the value to store. Must be a plain object.
     * @param value - The plain object to store. Functions, Symbols, arrays, `null`, and circular structures are rejected.
     * @throws {@link LockedError} If called while locked (master-password mode).
     * @throws {@link ValidationError} If `value` is not a plain JSON-serializable object.
     * @throws {@link StorageFullError} If localStorage quota is exceeded.
     * @throws {@link PersistenceError} If the integrity check after write fails.
     */
    setData<T extends Record<string, unknown>>(value: T): Promise<void>;
    /**
     * Export the store into a portable JSON bundle (v3).
     *
     * @param customExportPassword - Optional export password. **Required** in device mode.
     * @returns The serialized bundle string.
     * @throws {@link ExportError} If password is missing/blank in device mode.
     * @throws {@link LockedError} If called while locked (master-password mode).
     *
     * @remarks
     * - In master-password mode:
     *   - With no `customExportPassword`, the bundle is marked `mPw=true` and remains protected by the master password.
     *   - With a `customExportPassword`, the export is portable and **independent** of the master password.
     * - In device mode, you must provide a `customExportPassword` to produce a portable bundle.
     */
    exportData(customExportPassword?: string): Promise<string>;
    /**
     * Import a previously exported bundle (v2/v3). Returns a discriminator describing the protection used.
     *
     * @param serialized - The serialized bundle string.
     * @param password - The password required to unwrap the bundle:
     *   - For master-protected bundles: the **master password**.
     *   - For custom-export bundles: the **export password**.
     * @returns `"masterPassword"` when the imported bundle is protected by a master password; `"customExportPassword"` otherwise.
     * @throws {@link ImportError} On invalid structure, invalid base64, missing password, or wrong password.
     *
     * @remarks
     * - Master-protected imports transition the instance to **locked master-password mode**.
     * - Custom-export imports transition the instance to **device mode** and re-wrap the DEK under the device KEK.
     * - v2 bundles are migrated to v3 automatically with AAD binding.
     */
    importData(serialized: string, password?: string): Promise<string>;
    /**
     * Clear all local state and persisted content for this instance.
     *
     * @remarks
     * - Clears the session KEK/DEK from memory.
     * - Removes the localStorage bundle.
     * - Deletes the device KEK record in IndexedDB **for this instance’s namespace** (surgical delete).
     * - Re-initializes the store to a fresh device-mode v3 bundle (empty object).
     */
    clear(): Promise<void>;
    /** @internal Persist current config to localStorage (with integrity check and error wrapping). */
    persist(): void;
    /** @internal Assert a config is loaded; throw if not present (used by state methods). */
    requireConfig(): void;
    /** @internal Assert DEK is present (unlocked); throw otherwise. */
    requireUnlocked(): void;
    /** @internal Retrieve the in-RAM session KEK or throw if locked. */
    sessionKekOrThrow(): CryptoKey;
    /** @internal Ensure DEK is loaded (unwraps with device KEK or session KEK as needed). */
    ensureDekLoaded(): Promise<void>;
    /**
     * @internal
     * Unwrap the DEK using the supplied KEK and optional AAD; optionally make the DEK extractable for re-wrapping.
     *
     * @param kek - Wrapping key.
     * @param forWrapping - If `true`, unwraps the DEK as extractable (to allow re-wrap); otherwise non-extractable.
     * @param aad - AAD to bind to AES-GCM unwrap (versioned/contextual).
     */
    unwrapDekWithKek(kek: CryptoKey, forWrapping: boolean, aad?: Uint8Array): Promise<void>;
    /**
     * @internal Validate a parsed bundle semantically (rounds/salt rules, both-or-none data, base64 fields).
     * Throws {@link ImportError} with a precise reason on failure.
     */
    validateBundle(bundle: PersistedConfig): void;
    /**
     * @internal Decrypt the current data object (returns an empty object if data is not present).
     */
    decryptCurrentData(): Promise<Record<string, unknown>>;
    /**
     * @internal Migrate a v2 bundle into a v3 bundle with AAD binding and persist it.
     *
     * @param mode - `"device"` or `"master"` to select the correct header salt/rounds semantics.
     * @param v2 - The v2 persisted config to migrate.
     * @param kek - The KEK appropriate for the selected mode (device or master).
     */
    migrateV2ToV3(mode: "device" | "master", v2: PersistedConfigV2, kek: CryptoKey): Promise<void>;
}
