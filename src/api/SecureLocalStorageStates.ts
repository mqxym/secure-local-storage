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
import { SLS_CONSTANTS } from "../constants";
import { StorageService } from "../storage/StorageService";
import type { PersistedConfig, PersistedConfigV2, PersistedConfigV3 } from "../types";
import { base64ToBytes } from "../utils/base64";
import {  SecureDataView } from "../utils/secureDataView";
import { LockedState } from "./states/LockedState";
import { DeviceModeState } from "./states/DeviceModeState";
import type { IdbConfig } from "../crypto/DeviceKeyProvider";
import {
  ImportError,
  LockedError,
} from "../errors";
import { VersionManager } from "./sls/VersionManager";
import { State } from "./states/BaseState";
import { InitialState } from "./states/InitialState";
import { Portability } from "./sls/Portability";

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
export class SecureLocalStorage {
  /** @internal Backing state machine (Initial → DeviceMode|Locked → MasterPassword). */
  private state: State;

  /** @internal Local storage service for the serialized bundle. */
  public readonly store: StorageService;

  /** @internal Crypto primitives (AES-GCM, wrap/unwrap, salt). */
  public readonly enc = new EncryptionManager();

  /**
   * Session cache for a derived master-password KEK (in RAM only).
   * @internal
   */
  public readonly session = new SessionKeyCache();

  /**
   * The currently loaded config header+data (v2/v3). `null` until initialization completes or a fresh store is created.
   * @internal
   */
  public config: PersistedConfig | null = null;

  /**
   * The currently unwrapped DEK for the session, or `null` if locked or not yet loaded.
   * @internal
   */
  public dek: CryptoKey | null = null;

  /** @internal Resolves after InitialState.initialize(). All public async methods await this barrier. */
  private ready: Promise<void>;

  /**
   * Resolved IndexedDB namespace used for device KEK persistence.
   * @remarks
   * Propagated to {@link DeviceKeyProvider} calls, including surgical deletes and rotations.
   */
  public readonly idbConfig: { dbName: string; storeName: string; keyId: string };

  /**
   * The storage key string used for persistence and AAD binding (v3).
   * @see {@link SecureLocalStorageOptions.storageKey}
   */
  public readonly storageKeyStr: string;

  /** @internal Version helper to build AAD and validate/migrate between v2 and v3. */
  public readonly versionManager: VersionManager;

  /**
   * Last reason why a store was reset during initialization.
   * - `"invalid-config"` — persisted payload failed structural or base64 checks.
   * - `"device-kek-mismatch"` — unwrap with device KEK failed; store was reinitialized.
   *
   * @internal
   */
  public lastResetReason: "invalid-config" | "device-kek-mismatch" | null = null;

  /** @internal Exposed for tests: current data version. */
  public readonly DATA_VERSION: number = SLS_CONSTANTS.MIGRATION_TARGET_VERSION;

  /** @internal Indirection for tests/mocking. */
  public readonly deviceKeyProvider = DeviceKeyProvider;

  /** @internal Indirection for tests/mocking. */
  public readonly deriveKekFromPassword = deriveKekFromPassword;

  /**
   * Create a new SecureLocalStorage instance.
   *
   * @param opts - Optional configuration for storage key and KEK persistence namespace.
   *
   * @remarks
   * Construction kicks off async initialization. Public async methods await the internal `ready` barrier to ensure
   * the store is ready before operating.
   */
  constructor(opts?: SecureLocalStorageOptions) {
    this.storageKeyStr = opts?.storageKey ?? SLS_CONSTANTS.STORAGE_KEY;
    this.store = new StorageService(this.storageKeyStr);
    this.idbConfig = {
      dbName: opts?.idbConfig?.dbName ?? SLS_CONSTANTS.IDB.DB_NAME,
      storeName: opts?.idbConfig?.storeName ?? SLS_CONSTANTS.IDB.STORE,
      keyId: opts?.idbConfig?.keyId ?? SLS_CONSTANTS.IDB.ID,
    };
    this.versionManager = new VersionManager(this.storageKeyStr, this.idbConfig, this.enc);
    this.state = new InitialState(this);
    this.ready = this.state.initialize();
  }

  /** @internal State transition helper (do not call directly). */
  public transitionTo(state: State): void {
    this.state = state;
  }

  /**
   * Returns `true` if the store is protected by a master password.
   *
   * @returns Whether master-password mode is active.
   *
   * @remarks
   * - In device mode this is `false`.
   * - In master-password mode, a fresh instance in a new session will also be {@link isLocked locked} until {@link unlock}.
   */
  public isUsingMasterPassword(): boolean {
    return this.state.isUsingMasterPassword();
  }

  /**
   * Returns `true` if the session is locked (master-password mode and password not yet provided).
   *
   * @returns `true` when in master-password mode and locked; otherwise `false`.
   *
   * @remarks
   * - Device mode is never locked.
   * - After calling {@link lock}, this becomes `true` until {@link unlock}.
   */
  public isLocked(): boolean {
    return this.state.isLocked();
  }

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
  public async unlock(masterPassword: string): Promise<void> {
    await this.ready;
    return this.state.unlock(masterPassword);
  }

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
  public async setMasterPassword(masterPassword: string): Promise<void> {
    await this.ready;
    return this.state.setMasterPassword(masterPassword);
  }

  /**
   * Remove master-password protection and return to device mode.
   *
   * @throws {@link LockedError} If called while locked.
   * @throws {@link ModeError} If no master password is set (i.e., already in device mode).
   *
   * @remarks
   * Rewraps the DEK under the device KEK; the session remains unlocked in device mode.
   */
  public async removeMasterPassword(): Promise<void> {
    await this.ready;
    return this.state.removeMasterPassword();
  }

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
  public async rotateMasterPassword(oldMasterPassword: string, newMasterPassword: string): Promise<void> {
    await this.ready;
    return this.state.rotateMasterPassword(oldMasterPassword, newMasterPassword);
  }

  /**
   * Lock the current session (master-password mode only).
   *
   * @remarks
   * - Clears the in-RAM derived KEK and DEK; persisted data remains intact.
   * - Device mode ignores `lock()` (no effect).
   */
  public lock(): void {
    this.state.lock();
  }

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
  public async rotateKeys(): Promise<void> {
    await this.ready;
    return this.state.rotateKeys();
  }

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
  public async getData<T extends Record<string, unknown> = Record<string, unknown>>(): Promise<SecureDataView<T>> {
    await this.ready;
    return this.state.getData();
  }

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
  public async setData<T extends Record<string, unknown>>(value: T): Promise<void> {
    await this.ready;
    return this.state.setData(value);
  }

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
  public async exportData(customExportPassword?: string): Promise<string> {
    await this.ready;
    return this.state.exportData(customExportPassword);
  }

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
  public async importData(serialized: string, password?: string): Promise<string> {
    await this.ready;
 
    const { bundle, isMasterProtected } = Portability.parseAndClassify(serialized, SLS_CONSTANTS.SUPPORTED_VERSIONS);   

    this.validateBundle(bundle);

    if (typeof password !== "string" || password.trim().length === 0) {
      throw new ImportError(
        isMasterProtected ? "Master password required to import"
                          : "Export password required to import"
      );
    }

    const ctx = this.versionManager.isV3(bundle) ? (bundle.header.ctx ?? "store") : undefined;
    const wrapAad = this.versionManager.isV3(bundle) ? this.versionManager.buildWrapAad(ctx!, bundle.header.v) : undefined;
    const dataAadBuilder = (iv: string, wk: string) =>
      this.versionManager.isV3(bundle) ? this.versionManager.buildDataAad(ctx!, bundle.header.v, iv, wk) : undefined;

    if (isMasterProtected) {
      try {
        const kek = await deriveKekFromPassword(password, base64ToBytes(bundle.header.salt), (bundle.header as any).rounds);
        const dek = await this.enc.unwrapDek(bundle.header.iv, bundle.header.wrappedKey, kek, false, wrapAad);
        if (bundle.data.iv && bundle.data.ciphertext) {
          const dataAad = dataAadBuilder(bundle.header.iv, bundle.header.wrappedKey);
          await this.enc.decryptData<Record<string, unknown>>(dek, bundle.data.iv, bundle.data.ciphertext, dataAad);
        }
      } catch {
        throw new ImportError("Invalid master password or corrupted export data");
      }
      if (!this.versionManager.isV3(bundle) || (this.versionManager.isV3(bundle) && bundle.header.ctx !== "store")) {
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
        this.config = bundle as PersistedConfigV3;
      }

      this.dek = null;
      this.session.clear();
      this.persist();
      this.transitionTo(new LockedState(this));
      return "masterPassword";
    }

    try {
      const exportKek = await deriveKekFromPassword(password, base64ToBytes(bundle.header.salt), (bundle.header as any).rounds);
      const extractableDek = await this.enc.unwrapDek(bundle.header.iv, bundle.header.wrappedKey, exportKek, true, wrapAad);

      const deviceKek = await DeviceKeyProvider.getKey(this.idbConfig);

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
      this.transitionTo(new DeviceModeState(this));
      return "customExportPassword";
    } catch {
      throw new ImportError("Invalid export password or corrupted export data");
    }
  }

  /**
   * Clear all local state and persisted content for this instance.
   *
   * @remarks
   * - Clears the session KEK/DEK from memory.
   * - Removes the localStorage bundle.
   * - Deletes the device KEK record in IndexedDB **for this instance’s namespace** (surgical delete).
   * - Re-initializes the store to a fresh device-mode v3 bundle (empty object).
   */
  public async clear(): Promise<void> {
    await this.ready;
    return this.state.clear();
  }

  /** @internal Persist current config to localStorage (with integrity check and error wrapping). */
  public persist(): void {
    this.store.set(this.config!);
  }

  /** @internal Assert a config is loaded; throw if not present (used by state methods). */
  public requireConfig(): void {
    if (!this.config) throw new ImportError("No configuration present");
  }

  /** @internal Assert DEK is present (unlocked); throw otherwise. */
  public requireUnlocked(): void {
    if (!this.dek) throw new LockedError();
  }

  /** @internal Retrieve the in-RAM session KEK or throw if locked. */
  public sessionKekOrThrow(): CryptoKey {
    const { salt, rounds } = this.config!.header as any;
    const kek = this.session.match(salt, rounds);
    if (!kek) throw new LockedError("Session locked.");
    return kek;
  }

  /** @internal Ensure DEK is loaded (unwraps with device KEK or session KEK as needed). */
  public async ensureDekLoaded(): Promise<void> {
    if (this.dek) return;
    if (this.isUsingMasterPassword()) {
      const kek = this.sessionKekOrThrow();
      await this.unwrapDekWithKek(kek, false, this.versionManager.getAadFor("wrap", this.config!));
    } else {
      const deviceKek = await DeviceKeyProvider.getKey(this.idbConfig);
      await this.unwrapDekWithKek(deviceKek, false, this.versionManager.getAadFor("wrap", this.config!));
    }
  }

  /**
   * @internal
   * Unwrap the DEK using the supplied KEK and optional AAD; optionally make the DEK extractable for re-wrapping.
   *
   * @param kek - Wrapping key.
   * @param forWrapping - If `true`, unwraps the DEK as extractable (to allow re-wrap); otherwise non-extractable.
   * @param aad - AAD to bind to AES-GCM unwrap (versioned/contextual).
   */
  public async unwrapDekWithKek(kek: CryptoKey, forWrapping: boolean, aad?: Uint8Array): Promise<void> {
    this.dek = await this.enc.unwrapDek(this.config!.header.iv, this.config!.header.wrappedKey, kek, forWrapping, aad);
  }

  /**
   * @internal Validate a parsed bundle semantically (rounds/salt rules, both-or-none data, base64 fields).
   * Throws {@link ImportError} with a precise reason on failure.
   */
  public validateBundle(bundle: PersistedConfig): void {
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

  /**
   * @internal Decrypt the current data object (returns an empty object if data is not present).
   */
  public async decryptCurrentData(): Promise<Record<string, unknown>> {
    if (!this.config!.data.iv || !this.config!.data.ciphertext) return {};
    const aad = this.versionManager.getAadFor("data", this.config);
    return await this.enc.decryptData<Record<string, unknown>>(
      this.dek!, this.config!.data.iv, this.config!.data.ciphertext, aad
    );
  }

  /**
   * @internal Migrate a v2 bundle into a v3 bundle with AAD binding and persist it.
   *
   * @param mode - `"device"` or `"master"` to select the correct header salt/rounds semantics.
   * @param v2 - The v2 persisted config to migrate.
   * @param kek - The KEK appropriate for the selected mode (device or master).
   */
  public async migrateV2ToV3(
    mode: "device" | "master",
    v2: PersistedConfigV2,
    kek: CryptoKey
  ): Promise<void> {
    const dek = await this.enc.unwrapDek(v2.header.iv, v2.header.wrappedKey, kek, true, undefined);
    const plain = v2.data.iv && v2.data.ciphertext
      ? await this.enc.decryptData<Record<string, unknown>>(dek, v2.data.iv, v2.data.ciphertext, undefined)
      : {};

    const ctx: PersistedConfigV3["header"]["ctx"] = "store";
    const wrapAad = this.versionManager.buildWrapAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION);
    const { ivWrap, wrappedKey } = await this.enc.wrapDek(dek, kek, wrapAad);

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

    if (mode === "device") {
      const deviceKek = kek;
      this.dek = await this.enc.unwrapDek(ivWrap, wrappedKey, deviceKek, false, wrapAad);
      this.session.clear();
    } else {
      const masterKek = kek;
      this.dek = await this.enc.unwrapDek(ivWrap, wrappedKey, masterKek, false, wrapAad);
    }

    this.persist();
  }
}