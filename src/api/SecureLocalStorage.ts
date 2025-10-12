import { EncryptionManager } from "../crypto/EncryptionManager";
import { DeviceKeyProvider } from "../crypto/DeviceKeyProvider";
import { deriveKekFromPassword } from "../crypto/KeyDerivation";
import { SessionKeyCache } from "../crypto/SessionKeyCache";
import { SLS_CONSTANTS } from "../constants";
import { StorageService } from "../storage/StorageService";
import type { PersistedConfig, PersistedConfigV2, PersistedConfigV3 } from "../types";
import { base64ToBytes } from "../utils/base64";
import { toPlainJson } from "../utils/json";
import { makeSecureDataView, SecureDataView } from "../utils/secureDataView";
import type { IdbConfig } from "../crypto/DeviceKeyProvider";
import {
  ExportError,
  ImportError,
  LockedError,
  ModeError,
  ValidationError
} from "../errors";
import { VersionManager } from "./sls/VersionManager";

/**
 * Configuration options for initializing SecureLocalStorage.
 */
export interface SecureLocalStorageOptions {
  storageKey?: string;
  idbConfig?: Partial<IdbConfig>;
}

/**
 * Provides a secure local storage solution for web applications, encrypting data at rest.
 *
 * It supports two main modes of operation:
 * - **Device-bound:** Data is encrypted with a key stored in the browser's IndexedDB.
 *   This is the default mode and requires no user-provided password.
 * - **Password-protected:** Data is encrypted with a key derived from a user-provided master password.
 *
 * The class handles key management, encryption, decryption, and data migration between versions.
 */
export class SecureLocalStorage {
  private readonly store: StorageService;
  private readonly enc = new EncryptionManager();
  private readonly session = new SessionKeyCache();
  private config: PersistedConfig | null = null;
  private dek: CryptoKey | null = null;
  private ready: Promise<void>;
  private readonly idbConfig: { dbName: string; storeName: string; keyId: string };
  private readonly storageKeyStr: string;
  private readonly versionManager: VersionManager;

  private lastResetReason: "invalid-config" | "device-kek-mismatch" | null = null;

  /** Kept as 2 for backward compat/tests */
  public readonly DATA_VERSION: number = SLS_CONSTANTS.CURRENT_DATA_VERSION;

  constructor(opts?: SecureLocalStorageOptions) {
    this.storageKeyStr = opts?.storageKey ?? SLS_CONSTANTS.STORAGE_KEY;
    this.store = new StorageService(this.storageKeyStr);
    this.idbConfig = {
      dbName: opts?.idbConfig?.dbName ?? SLS_CONSTANTS.IDB.DB_NAME,
      storeName: opts?.idbConfig?.storeName ?? SLS_CONSTANTS.IDB.STORE,
      keyId: opts?.idbConfig?.keyId ?? SLS_CONSTANTS.IDB.ID,
    };
    this.versionManager = new VersionManager(this.storageKeyStr, this.idbConfig, this.enc);
    this.ready = this.initialize();
  }

  // --------------------------- public API ---------------------------

  /**
   * Checks if the store is protected by a master password.
   *
   * @returns `true` if a master password is set, `false` otherwise.
   */
  public isUsingMasterPassword(): boolean {
    return (this.config?.header.rounds ?? 1) > 1;
  }

  /**
   * Checks if the store is currently locked.
   * This is only relevant when a master password is used.
   *
   * @returns `true` if the store is locked, `false` otherwise.
   */
  public isLocked(): boolean {
    return this.isUsingMasterPassword() && !this.dek;
  }

  /**
   * Unlocks the store with the provided master password.
   *
   * @param masterPassword - The master password to unlock the store.
   * @throws {ValidationError} If the master password is empty or invalid.
   */
  async unlock(masterPassword: string): Promise<void> {
    await this.ready;
    if (!this.config) return;
    if (!this.isUsingMasterPassword()) return;

    if (typeof masterPassword !== "string" || masterPassword.trim().length === 0) {
      throw new ValidationError("masterPassword must be a non-empty string");
    }

    const { salt, rounds } = this.config.header;
    const kek = await deriveKekFromPassword(masterPassword, base64ToBytes(salt), rounds);

    // Unwrap using the correct AAD for current version/ctx
    try {
      this.session.set(kek, salt, rounds);
      await this.unwrapDekWithKek(kek, false, this.versionManager.getAadFor("wrap", this.config));
    } catch {
      this.session.clear();
      throw new ValidationError("Invalid master password");
    }

    // Auto-migrate v2 -> v3 on unlock (master mode)
    if (this.versionManager.isV2(this.config)) {
      await this.migrateV2ToV3("master", this.config, kek);
    }
  }

  /**
   * Sets a new master password, transitioning the store from device-bound to password-protected mode.
   *
   * @param masterPassword The password to set. Must be a non-empty string.
   * @throws {ModeError} If a master password is already set.
   * @throws {ValidationError} If the master password is empty.
   */
  async setMasterPassword(masterPassword: string): Promise<void> {
    await this.ready;
    this.requireConfig();
    if (this.isUsingMasterPassword()) {
      throw new ModeError("Master password already set; use rotateMasterPassword()");
    }
    const pw = typeof masterPassword === "string" ? masterPassword.trim() : "";
    if (pw.length === 0) {
      throw new ValidationError("masterPassword must be a non-empty string");
    }

    // Unwrap existing DEK (device mode, so use device key + current AAD)
    const deviceKek = await DeviceKeyProvider.getKey(this.idbConfig);
    await this.unwrapDekWithKek(deviceKek, true, this.versionManager.getAadFor("wrap", this.config!));

    // Decrypt existing data using its current AAD (v2 has none)
    const plain = await this.decryptCurrentData();

    // Build new master KEK
    const saltB64 = this.enc.generateSaltB64();
    const rounds = SLS_CONSTANTS.ARGON2.ITERATIONS;
    const kek = await deriveKekFromPassword(masterPassword, base64ToBytes(saltB64), rounds);

    // Rewrap with v3 store AAD
    const ctx: PersistedConfigV3["header"]["ctx"] = "store";
    const wrapAad = this.versionManager.buildWrapAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION);
    const wrapped = await this.enc.wrapDek(this.dek!, kek, wrapAad);

    // Encrypt data under v3 store AAD bound to new header
    const dataAad = this.versionManager.buildDataAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION, wrapped.ivWrap, wrapped.wrappedKey);
    const { iv, ciphertext } = await this.enc.encryptData(this.dek!, plain, dataAad);

    this.config = {
      header: {
        v: SLS_CONSTANTS.MIGRATION_TARGET_VERSION,
        salt: saltB64,
        rounds,
        iv: wrapped.ivWrap,
        wrappedKey: wrapped.wrappedKey,
        ctx
      },
      data: { iv, ciphertext }
    };

    // Keep session unlocked (cache kek) and unwrap DEK for use
    this.session.set(kek, saltB64, rounds);
    this.dek = await this.enc.unwrapDek(wrapped.ivWrap, wrapped.wrappedKey, kek, false, wrapAad);
    this.persist();
  }

  /**
   * Removes the master password, transitioning the store to device-bound mode.
   *
   * @throws {ModeError} If no master password is set.
   * @throws {LockedError} If the store is locked.
   */
  async removeMasterPassword(): Promise<void> {
    await this.ready;
    this.requireConfig();
    if (!this.isUsingMasterPassword()) throw new ModeError("No master password is set");
    this.requireUnlocked();

    // Unwrap DEK for wrapping
    await this.unwrapDekWithKek(this.sessionKekOrThrow(), true, this.versionManager.getAadFor("wrap", this.config!));

    // Decrypt data under current AAD
    const plain = await this.decryptCurrentData();

    const deviceKek = await DeviceKeyProvider.getKey(this.idbConfig);

    // Wrap with device kek under v3 store AAD
    const ctx: PersistedConfigV3["header"]["ctx"] = "store";
    const wrapAad = this.versionManager.buildWrapAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION);
    const { ivWrap, wrappedKey } = await this.enc.wrapDek(this.dek!, deviceKek, wrapAad);

    // Encrypt data with v3 data AAD bound to new header
    const dataAad = this.versionManager.buildDataAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION, ivWrap, wrappedKey);
    const { iv, ciphertext } = await this.enc.encryptData(this.dek!, plain, dataAad);

    this.config = {
      header: {
        v: SLS_CONSTANTS.MIGRATION_TARGET_VERSION,
        salt: "",
        rounds: 1,
        iv: ivWrap,
        wrappedKey,
        ctx
      },
      data: { iv, ciphertext }
    };

    // In device mode, keep DEK unwrapped
    this.dek = await this.enc.unwrapDek(ivWrap, wrappedKey, deviceKek, false, wrapAad);
    this.session.clear();
    this.persist();
  }

  /**
   * Rotates the master password.
   *
   * @param oldMasterPassword The current master password.
   * @param newMasterPassword The new master password to set.
   * @throws {ValidationError} If the new master password is empty.
   * @throws {LockedError} If the old master password is incorrect.
   */
  async rotateMasterPassword(oldMasterPassword: string, newMasterPassword: string): Promise<void> {
    await this.ready;
    this.requireConfig();

    const newPw = typeof newMasterPassword === "string" ? newMasterPassword.trim() : "";
    if (newPw.length === 0) {
      throw new ValidationError("newMasterPassword must be a non-empty string");
    }

    if (!this.isUsingMasterPassword()) {
      await this.unlock(oldMasterPassword); // no-op in device mode
      await this.setMasterPassword(newMasterPassword);
      return;
    }

    await this.unlock(oldMasterPassword);
    this.requireUnlocked();

    // Unwrap DEK for wrapping and decrypt current data
    await this.unwrapDekWithKek(this.sessionKekOrThrow(), true, this.versionManager.getAadFor("wrap", this.config!));
    const plain = await this.decryptCurrentData();

    // Build new KEK
    const saltB64 = this.enc.generateSaltB64();
    const rounds = SLS_CONSTANTS.ARGON2.ITERATIONS;
    const newKek = await deriveKekFromPassword(newMasterPassword, base64ToBytes(saltB64), rounds);

    // Rewrap with v3 store AAD
    const ctx: PersistedConfigV3["header"]["ctx"] = "store";
    const wrapAad = this.versionManager.buildWrapAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION);
    const { ivWrap, wrappedKey } = await this.enc.wrapDek(this.dek!, newKek, wrapAad);

    // Re-encrypt data bound to new header
    const dataAad = this.versionManager.buildDataAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION, ivWrap, wrappedKey);
    const { iv, ciphertext } = await this.enc.encryptData(this.dek!, plain, dataAad);

    this.config = {
      header: {
        v: SLS_CONSTANTS.MIGRATION_TARGET_VERSION,
        salt: saltB64,
        rounds,
        iv: ivWrap,
        wrappedKey,
        ctx
      },
      data: { iv, ciphertext }
    };

    this.session.set(newKek, saltB64, rounds);
    this.dek = await this.enc.unwrapDek(ivWrap, wrappedKey, newKek, false, wrapAad);

    this.persist();
  }

  /**
   * Locks the store, requiring `unlock()` to be called before further operations.
   * This is only effective in password-protected mode.
   */
  lock(): void {
    this.session.clear();
    this.dek = null;
  }

  /**
   * Rotates the underlying device key, re-encrypting all data.
   * This is only available in device-bound mode.
   *
   * @throws {ModeError} If a master password is set.
   */
  async rotateKeys(): Promise<void> {
    await this.ready;
    this.requireConfig();
    if (this.isUsingMasterPassword()) {
      throw new ModeError("rotateKeys is allowed only in password-less mode");
    }
    const deviceKek = await DeviceKeyProvider.getKey(this.idbConfig);

    // Ensure DEK loaded and decrypt data under current AAD
    await this.unwrapDekWithKek(deviceKek, false, this.versionManager.getAadFor("wrap", this.config!));
    const plain = await this.decryptCurrentData();

    // Generate new DEK and new device KEK, re-encrypt data
    const newDek = await this.enc.createDek();

    // Wrap with rotated device kek under v3 store AAD
    const newDeviceKek = await DeviceKeyProvider.rotateKey(this.idbConfig);
    const ctx: PersistedConfigV3["header"]["ctx"] = "store";
    const wrapAad = this.versionManager.buildWrapAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION);
    const { ivWrap, wrappedKey } = await this.enc.wrapDek(newDek, newDeviceKek, wrapAad);

    // Encrypt with v3 data AAD bound to new header
    const dataAad = this.versionManager.buildDataAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION, ivWrap, wrappedKey);
    const { iv, ciphertext } = await this.enc.encryptData(newDek, plain, dataAad);

    this.config = {
      header: {
        v: SLS_CONSTANTS.MIGRATION_TARGET_VERSION,
        salt: "",
        rounds: 1,
        iv: ivWrap,
        wrappedKey,
        ctx
      },
      data: { iv, ciphertext }
    };

    // Keep session convenient (unwrapped in memory)
    this.dek = await this.enc.unwrapDek(ivWrap, wrappedKey, newDeviceKek, false, wrapAad);

    // Clear plaintext copy
    for (const k of Object.keys(plain)) (plain as Record<string, unknown>)[k] = null;

    this.persist();
  }

  /**
   * Retrieves the stored data.
   *
   * @returns A promise that resolves with a `SecureDataView` of the stored data.
   *          The view is a read-only proxy of the decrypted data.
   * @throws {LockedError} If the store is locked.
   * @throws {ValidationError} If the decrypted data is not a plain object.
   */
  async getData<T extends Record<string, unknown> = Record<string, unknown>>(): Promise<SecureDataView<T>> {
    await this.ready;
    this.requireConfig();
    await this.ensureDekLoaded();
    if (!this.config!.data.iv || !this.config!.data.ciphertext) {
      return makeSecureDataView({} as T);
    }

    const dataAad = this.versionManager.getAadFor("data", this.config);
    const obj = await this.enc.decryptData<unknown>(this.dek!, this.config!.data.iv, this.config!.data.ciphertext, dataAad);

    const isPlain =
      !!obj &&
      typeof obj === "object" &&
      !Array.isArray(obj) &&
      Object.getPrototypeOf(obj as object) === Object.prototype;

    if (!isPlain) {
      throw new ValidationError("Stored data must be a plain object");
    }
    return makeSecureDataView(obj as T);
  }

  /**
   * Saves data to the store. The value must be a plain object.
   *
   * @param value The plain object to save.
   * @throws {LockedError} If the store is locked.
   * @throws {ValidationError} If the value is not a plain object.
   */
  async setData<T extends Record<string, unknown>>(value: T): Promise<void> {
    await this.ready;
    this.requireConfig();
    await this.ensureDekLoaded();

    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new ValidationError("Data must be a plain object");
    }

    const plain = toPlainJson(value);
    const dataAad = this.versionManager.getAadFor("data", this.config);
    const { iv, ciphertext } = await this.enc.encryptData(this.dek!, plain, dataAad);
    this.config!.data = { iv, ciphertext };
    this.persist();
  }

  /**
   * Exports the stored data as a serialized, protected string.
   *
   * @param customExportPassword An optional password to encrypt the exported data.
   *                             If not provided in master password mode, the master password is used.
   *                             Required in device-bound mode.
   * @returns A promise that resolves with the serialized data bundle.
   * @throws {ExportError} If a password is required but not provided.
   */
  async exportData(customExportPassword?: string): Promise<string> {
    await this.ready;
    this.requireConfig();

    // Determine source decrypt context (current store)
    await this.ensureDekLoaded();
    const plain = await this.decryptCurrentData();

    // Determine active KEK used by the current store (device or master)
    const activeKek = this.isUsingMasterPassword()
      ? this.sessionKekOrThrow()
      : await DeviceKeyProvider.getKey(this.idbConfig);

    // IMPORTANT: Re-unwrap as extractable so we can wrap for export
    await this.unwrapDekWithKek(activeKek, true, this.versionManager.getAadFor("wrap", this.config!));

    // Build export KEK & header fields
    let saltB64: string;
    let rounds: number;
    let kek: CryptoKey;
    let mPw: boolean;

    if (!customExportPassword && this.isUsingMasterPassword()) {
      // Use current master salt/rounds and the session KEK
      saltB64 = this.config!.header.salt;
      rounds = this.config!.header.rounds;
      kek = this.sessionKekOrThrow();
      mPw = true;
    } else {
      if (!customExportPassword) {
        throw new ExportError("Export password required in device mode");
      }
      if (typeof customExportPassword !== "string" || customExportPassword.trim().length === 0) {
        throw new ExportError("Export password must be a non-empty string");
      }
      saltB64 = this.enc.generateSaltB64();
      rounds = SLS_CONSTANTS.ARGON2.ITERATIONS;
      kek = await deriveKekFromPassword(customExportPassword, base64ToBytes(saltB64), rounds);
      mPw = false;
    }

    // Rewrap under export AAD and re-encrypt data bound to that header
    const ctx: PersistedConfigV3["header"]["ctx"] = "export";
    const wrapAad = this.versionManager.buildWrapAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION);
    const { ivWrap, wrappedKey } = await this.enc.wrapDek(this.dek!, kek, wrapAad);
    const dataAad = this.versionManager.buildDataAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION, ivWrap, wrappedKey);
    const { iv, ciphertext } = await this.enc.encryptData(this.dek!, plain, dataAad);

    const bundle: PersistedConfigV3 = {
      header: {
        v: SLS_CONSTANTS.MIGRATION_TARGET_VERSION,
        salt: saltB64,
        rounds,
        iv: ivWrap,
        wrappedKey,
        mPw,
        ctx
      },
      data: { iv, ciphertext }
    };
    return JSON.stringify(bundle);
  }

  /**
   * Imports data from a serialized string, overwriting the current store.
   *
   * @param serialized The serialized data bundle to import.
   * @param password The password required to decrypt the bundle, if it is protected.
   * @returns A promise that resolves with a string indicating the protection mode of the imported data ("masterPassword" or "customExportPassword").
   * @throws {ImportError} If the serialized data is invalid, corrupted, or the password is incorrect.
   */
  async importData(serialized: string, password?: string): Promise<string> {
    await this.ready;
    let t: unknown;
    try {  
      t = JSON.parse(serialized);
    } catch {
      throw new ImportError("Invalid export structure");
    }
    if (!t || typeof t !== "object" || typeof (t as any).header !== "object" || typeof (t as any).data !== "object") {
      throw new ImportError("Invalid export structure");
    }
    const bundle = t as PersistedConfig;

    if (!SLS_CONSTANTS.SUPPORTED_VERSIONS.includes(bundle.header.v as 2 | 3)) {
      throw new ImportError(`Unsupported export version ${(bundle as any).header?.v}`);
    }

    this.validateBundle(bundle);

    const isMasterProtected =
      (bundle as any).header.mPw === true ||
      ((bundle.header as any).rounds > 1 && (bundle as any).header.mPw !== false);

    if (typeof password !== "string" || password.length === 0) {
      throw new ImportError(isMasterProtected
        ? "Master password required to import"
        : "Export password required to import"
      );
    }

    // Select AAD context for the incoming bundle
    const ctx = this.versionManager.isV3(bundle) ? (bundle.header.ctx ?? "store") : undefined;
    const wrapAad = this.versionManager.isV3(bundle) ? this.versionManager.buildWrapAad(ctx!, bundle.header.v) : undefined;
    const dataAadBuilder = (iv: string, wk: string) =>
      this.versionManager.isV3(bundle) ? this.versionManager.buildDataAad(ctx!, bundle.header.v, iv, wk) : undefined;

    if (isMasterProtected) {
      try {
        const kek = await deriveKekFromPassword(password, base64ToBytes(bundle.header.salt), (bundle.header as any).rounds);
        // unwrap & (optionally) verify data
        const dek = await this.enc.unwrapDek(bundle.header.iv, bundle.header.wrappedKey, kek, false, wrapAad);
        if (bundle.data.iv && bundle.data.ciphertext) {
          const dataAad = dataAadBuilder(bundle.header.iv, bundle.header.wrappedKey);
          await this.enc.decryptData<Record<string, unknown>>(dek, bundle.data.iv, bundle.data.ciphertext, dataAad);
        }
      } catch {
        throw new ImportError("Invalid master password or corrupted export data");
      }
      // Accept bundle as-is (master mode) and persist into local store with ctx:"store" (and v3)
      // For master imports we keep master mode; but we must ensure local store uses ctx:"store"
      // If imported bundle is v2 or ctx:"export", rewrap/re-encrypt under store AAD.
      if (!this.versionManager.isV3(bundle) || (this.versionManager.isV3(bundle) && bundle.header.ctx !== "store")) {
        // Rewrap to store context & persist v3
        const kek = await deriveKekFromPassword(password, base64ToBytes(bundle.header.salt), (bundle.header as any).rounds);
        const dek = await this.enc.unwrapDek(bundle.header.iv, bundle.header.wrappedKey, kek, true, wrapAad);
        const ctxStore: PersistedConfigV3["header"]["ctx"] = "store";
        const wrapAadStore = this.versionManager.buildWrapAad(ctxStore, SLS_CONSTANTS.MIGRATION_TARGET_VERSION);
        const wrapped = await this.enc.wrapDek(dek, kek, wrapAadStore);
        const dataAadStore = this.versionManager.buildDataAad(ctxStore, SLS_CONSTANTS.MIGRATION_TARGET_VERSION, wrapped.ivWrap, wrapped.wrappedKey);
        const plain = bundle.data.iv && bundle.data.ciphertext
          ? await this.enc.decryptData<Record<string, unknown>>(dek, bundle.data.iv, bundle.data.ciphertext, dataAadBuilder(bundle.header.iv, bundle.header.wrappedKey))
          : {};
        const data = await this.enc.encryptData(dek, plain, dataAadStore);

        this.config = {
          header: {
            v: SLS_CONSTANTS.MIGRATION_TARGET_VERSION,
            salt: bundle.header.salt,
            rounds: (bundle.header as any).rounds,
            iv: wrapped.ivWrap,
            wrappedKey: wrapped.wrappedKey,
            ctx: ctxStore,
            mPw: true
          },
          data
        };
      } else {
        // Already store context & v3 -> adopt directly
        this.config = bundle as PersistedConfigV3;
      }

      this.dek = null; // locked until unlock()
      this.session.clear();
      this.persist();
      return "masterPassword";
    }

    // Custom export password path
    try {
      const exportKek = await deriveKekFromPassword(password, base64ToBytes(bundle.header.salt), (bundle.header as any).rounds);
      const extractableDek = await this.enc.unwrapDek(bundle.header.iv, bundle.header.wrappedKey, exportKek, true, wrapAad);

      const deviceKek = await DeviceKeyProvider.getKey(this.idbConfig);

      // Persist into local store with v3 ctx:"store"
      const ctxStore: PersistedConfigV3["header"]["ctx"] = "store";
      const wrapAadStore = this.versionManager.buildWrapAad(ctxStore, SLS_CONSTANTS.MIGRATION_TARGET_VERSION);
      const { ivWrap, wrappedKey } = await this.enc.wrapDek(extractableDek, deviceKek, wrapAadStore);
      const dataAadStore = this.versionManager.buildDataAad(ctxStore, SLS_CONSTANTS.MIGRATION_TARGET_VERSION, ivWrap, wrappedKey);

      const plain = bundle.data.iv && bundle.data.ciphertext
        ? await this.enc.decryptData<Record<string, unknown>>(extractableDek, bundle.data.iv, bundle.data.ciphertext, dataAadBuilder(bundle.header.iv, bundle.header.wrappedKey))
        : {};
      const data = await this.enc.encryptData(extractableDek, plain, dataAadStore);

      this.config = {
        header: {
          v: SLS_CONSTANTS.MIGRATION_TARGET_VERSION,
          salt: "",
          rounds: 1,
          iv: ivWrap,
          wrappedKey,
          ctx: ctxStore
        },
        data
      };
      this.dek = await this.enc.unwrapDek(ivWrap, wrappedKey, deviceKek, false, wrapAadStore);
      this.session.clear();
      this.persist();
      return "customExportPassword";
    } catch {
      throw new ImportError("Invalid export password or corrupted export data");
    }
  }

  /**
   * Clears all data from the store, including the device key, and reinitializes it.
   */
  async clear(): Promise<void> {
    await this.ready;
    this.session.clear();
    this.dek = null;
    this.store.clear();
    await DeviceKeyProvider.deletePersistent(this.idbConfig);
    await this.initialize(true);
  }

  // --------------------------- private helpers ---------------------------

  private async initialize(forceFresh = false): Promise<void> {
    if (forceFresh) {
      // Create fresh v3 store with empty object
      const dek = await this.enc.createDek();
      const deviceKek = await DeviceKeyProvider.getKey(this.idbConfig);

      const ctx: PersistedConfigV3["header"]["ctx"] = "store";
      const wrapAad = this.versionManager.buildWrapAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION);
      const { ivWrap, wrappedKey } = await this.enc.wrapDek(dek, deviceKek, wrapAad);
      const unwrappedDek = await this.enc.unwrapDek(ivWrap, wrappedKey, deviceKek, false, wrapAad);

      const dataAad = this.versionManager.buildDataAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION, ivWrap, wrappedKey);
      const { iv, ciphertext } = await this.enc.encryptData(unwrappedDek, {}, dataAad); // empty object

      this.config = {
        header: {
          v: SLS_CONSTANTS.MIGRATION_TARGET_VERSION,
          salt: "",
          rounds: 1,
          iv: ivWrap,
          wrappedKey,
          ctx
        },
        data: { iv, ciphertext }
      };
      this.dek = unwrappedDek;
      this.persist();
      return;
    }

    const existing = this.store.get();
    if (!this.versionManager.isValidConfig(existing)) {
      this.lastResetReason = "invalid-config";
      await this.initialize(true);
      return;
    }

    this.config = existing;

    // Auto-unlock (or migrate) in device mode
    if (!this.isUsingMasterPassword()) {
      const deviceKek = await DeviceKeyProvider.getKey(this.idbConfig);
      try {
        // Try unwrapping with proper AAD
        await this.unwrapDekWithKek(deviceKek, false, this.versionManager.getAadFor("wrap", existing));

        // If v2, migrate immediately
        if (this.versionManager.isV2(existing)) {
          await this.migrateV2ToV3("device", existing, deviceKek);
        }
      } catch {
        this.lastResetReason = "device-kek-mismatch";
        await this.initialize(true);
      }
    }
  }

  private persist(): void {
    this.store.set(this.config!);
  }

  private requireConfig(): void {
    if (!this.config) throw new ImportError("No configuration present");
  }

  private requireUnlocked(): void {
    if (!this.dek) throw new LockedError();
  }

  private sessionKekOrThrow(): CryptoKey {
    const { salt, rounds } = this.config!.header as any;
    const kek = this.session.match(salt, rounds);
    if (!kek) throw new LockedError("Session locked.");
    return kek;
  }

  private async ensureDekLoaded(): Promise<void> {
    if (this.dek) return;
    if (this.isUsingMasterPassword()) {
      const kek = this.sessionKekOrThrow();
      await this.unwrapDekWithKek(kek, false, this.versionManager.getAadFor("wrap", this.config!));
    } else {
      const deviceKek = await DeviceKeyProvider.getKey(this.idbConfig);
      await this.unwrapDekWithKek(deviceKek, false, this.versionManager.getAadFor("wrap", this.config!));
    }
  }

  private async unwrapDekWithKek(kek: CryptoKey, forWrapping: boolean, aad?: Uint8Array): Promise<void> {
    this.dek = await this.enc.unwrapDek(this.config!.header.iv, this.config!.header.wrappedKey, kek, forWrapping, aad);
  }

  private validateBundle(bundle: PersistedConfig): void {
    const h = bundle?.header as any;
    const d = bundle?.data as any;
    if (!h || !d) throw new ImportError("Invalid export structure");

    if (!Number.isInteger(h.rounds) || h.rounds < 1) throw new ImportError("Invalid header.rounds");

    if (h.rounds === 1) {
      if (h.salt !== "") throw new ImportError("Device-mode bundles must have empty salt");
    } else {
      if (typeof h.salt !== "string" || h.salt.length === 0) {
        throw new ImportError("Password-protected bundles must include non-empty salt");
      }
    }

    if ("mPw" in h && typeof h.mPw !== "boolean") {
      throw new ImportError("Invalid header.mPw");
    }
    if ("ctx" in h && !(h.ctx === "store" || h.ctx === "export")) {
      throw new ImportError("Invalid header.ctx");
    }

    if (typeof h.iv !== "string" || h.iv.length === 0) throw new ImportError("Invalid header.iv");
    if (typeof h.wrappedKey !== "string" || h.wrappedKey.length === 0) throw new ImportError("Invalid header.wrappedKey");
    if (typeof d.iv !== "string" || typeof d.ciphertext !== "string") {
      throw new ImportError("Invalid data section");
    }

    try {
      base64ToBytes(h.iv);
      base64ToBytes(h.wrappedKey);
      if (d.iv) base64ToBytes(d.iv);
      if (d.ciphertext) base64ToBytes(d.ciphertext);
    } catch {
      throw new ImportError("Invalid base64 data");
    }
  }

  // ---------- AAD helpers & version helpers ----------



  private async decryptCurrentData(): Promise<Record<string, unknown>> {
    if (!this.config!.data.iv || !this.config!.data.ciphertext) return {};
    const aad = this.versionManager.getAadFor("data", this.config);
    return await this.enc.decryptData<Record<string, unknown>>(
      this.dek!, this.config!.data.iv, this.config!.data.ciphertext, aad
    );
  }

  private async migrateV2ToV3(
    mode: "device" | "master",
    v2: PersistedConfigV2,
    kek: CryptoKey
  ): Promise<void> {
    // v2 unwrap & decrypt (no AAD)
    const dek = await this.enc.unwrapDek(v2.header.iv, v2.header.wrappedKey, kek, true /*extractable*/, undefined);
    const plain = v2.data.iv && v2.data.ciphertext
      ? await this.enc.decryptData<Record<string, unknown>>(dek, v2.data.iv, v2.data.ciphertext, undefined)
      : {};

    // Rewrap with v3 store AAD
    const ctx: PersistedConfigV3["header"]["ctx"] = "store";
    const wrapAad = this.versionManager.buildWrapAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION);
    const { ivWrap, wrappedKey } = await this.enc.wrapDek(dek, kek, wrapAad);

    // Re-encrypt data with v3 data AAD bound to new header
    const dataAad = this.versionManager.buildDataAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION, ivWrap, wrappedKey);
    const { iv, ciphertext } = await this.enc.encryptData(dek, plain, dataAad);

    this.config = {
      header: {
        v: SLS_CONSTANTS.MIGRATION_TARGET_VERSION,
        salt: mode === "device" ? "" : v2.header.salt,
        rounds: mode === "device" ? 1 : v2.header.rounds,
        iv: ivWrap,
        wrappedKey,
        ctx
      },
      data: { iv, ciphertext }
    };

    // Maintain unlocked status per mode
    if (mode === "device") {
      const deviceKek = kek;
      this.dek = await this.enc.unwrapDek(ivWrap, wrappedKey, deviceKek, false, wrapAad);
      this.session.clear();
    } else {
      const masterKek = kek;
      this.dek = await this.enc.unwrapDek(ivWrap, wrappedKey, masterKek, false, wrapAad);
      // Keep session (already set in unlock)
    }

    this.persist();
  }
}