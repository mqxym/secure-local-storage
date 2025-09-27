import { EncryptionManager } from "../crypto/EncryptionManager";
import { DeviceKeyProvider } from "../crypto/DeviceKeyProvider";
import { deriveKekFromPassword } from "../crypto/KeyDerivation";
import { SessionKeyCache } from "../crypto/SessionKeyCache";
import { SLS_CONSTANTS } from "../constants";
import { StorageService } from "../storage/StorageService";
import type { PersistedConfigV2 } from "../types";
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

export interface SecureLocalStorageOptions {
  /** Override the localStorage key (for multi-tenant apps or tests). */
  storageKey?: string;
  /** Override IndexedDB configuration (for multi-tenant apps or tests). */
  idbConfig?: Partial<IdbConfig>;
}

export class SecureLocalStorage {
  private readonly store: StorageService;
  private readonly enc = new EncryptionManager();
  private readonly session = new SessionKeyCache();
  private config: PersistedConfigV2 | null = null;
  private dek: CryptoKey | null = null;
  private ready: Promise<void>;
  private readonly idbConfig: { dbName: string; storeName: string; keyId: string };
  
  public readonly DATA_VERSION: number = SLS_CONSTANTS.CURRENT_DATA_VERSION;


  constructor(opts?: SecureLocalStorageOptions) {
    this.store = new StorageService(opts?.storageKey);
    this.idbConfig = {
      dbName: opts?.idbConfig?.dbName ?? SLS_CONSTANTS.IDB.DB_NAME,
      storeName: opts?.idbConfig?.storeName ?? SLS_CONSTANTS.IDB.STORE,
      keyId: opts?.idbConfig?.keyId ?? SLS_CONSTANTS.IDB.ID,
    };

    this.ready = this.initialize();
  }

  // --------------------------- public API ---------------------------

  public isUsingMasterPassword(): boolean {
    return (this.config?.header.rounds ?? 1) > 1;
  }


  /** Unlock session with master password (no-op in device mode / no data available ). */
  async unlock(masterPassword: string): Promise<void> {
    await this.ready;
    if (!this.config) return;
    if (!this.isUsingMasterPassword()) return; // already unlocked in device mode
    
    if (typeof masterPassword !== "string" || masterPassword.trim().length === 0) {
      throw new ValidationError("masterPassword must be a non-empty string");
    }

    const { salt, rounds } = this.config.header;
    const kek = await deriveKekFromPassword(masterPassword, base64ToBytes(salt), rounds);
    try {
      this.session.set(kek, salt, rounds);
      await this.unwrapDekWithKek(kek, false);
    } catch {
      this.session.clear();
      throw new ValidationError("Invalid master password");
    }
  }

  /** Set a master password (switch from device mode to master mode). */
  async setMasterPassword(masterPassword: string): Promise<void> {
    await this.ready;
    this.requireConfig();
    if (this.isUsingMasterPassword()) {
      throw new ModeError("Master password already set; use rotateMasterPassword()");
    }
    if (typeof masterPassword !== "string" || masterPassword.length === 0) {
      throw new ValidationError("masterPassword must be a non-empty string");
    }
    // Unwrap existing DEK for wrapping using device KEK
    const deviceKek = await DeviceKeyProvider.getKey(this.idbConfig);
    await this.unwrapDekWithKek(deviceKek, true);

    const saltB64 = this.enc.generateSaltB64();
    const kek = await deriveKekFromPassword(masterPassword, base64ToBytes(saltB64));
    const wrapped = await this.enc.wrapDek(this.dek!, kek);

    // Update header to master mode
    this.config!.header = {
      v: SLS_CONSTANTS.CURRENT_DATA_VERSION,
      salt: saltB64,
      rounds: SLS_CONSTANTS.ARGON2.ITERATIONS,
      iv: wrapped.ivWrap,
      wrappedKey: wrapped.wrappedKey
    };

    // Keep session unlocked (cache kek) and unwrap DEK for use
    this.session.set(kek, saltB64, SLS_CONSTANTS.ARGON2.ITERATIONS);
    this.dek = await this.enc.unwrapDek(wrapped.ivWrap, wrapped.wrappedKey, kek, false);
    this.persist();
  }

  /** Remove master password, re-wrapping DEK with device-bound KEK. Requires unlocked session. */
  async removeMasterPassword(): Promise<void> {
    await this.ready;
    this.requireConfig();
    if (!this.isUsingMasterPassword()) throw new ModeError("No master password is set");
    this.requireUnlocked();

    const deviceKek = await DeviceKeyProvider.getKey(this.idbConfig);
    // Ensure DEK is extractable for wrap
    await this.unwrapDekWithKek(this.sessionKekOrThrow(), true);
    const { ivWrap, wrappedKey } = await this.enc.wrapDek(this.dek!, deviceKek);

    this.config!.header = {
      v: SLS_CONSTANTS.CURRENT_DATA_VERSION,
      salt: "",
      rounds: 1,
      iv: ivWrap,
      wrappedKey
    };

    // In device mode, keep DEK unwrapped for convenience
    this.dek = await this.enc.unwrapDek(ivWrap, wrappedKey, deviceKek, false);
    this.session.clear(); // no master kek required now
    this.persist();
  }

  /** Rotate master password atomically. */
  async rotateMasterPassword(oldMasterPassword: string, newMasterPassword: string): Promise<void> {
    await this.ready;
    this.requireConfig();

    if (typeof newMasterPassword !== "string" || newMasterPassword.length === 0) {
      throw new ValidationError("newMasterPassword must be a non-empty string");
    }

    if (!this.isUsingMasterPassword()) {
      // unlock() is a no-op in device mode
      await this.unlock(oldMasterPassword);
      await this.setMasterPassword(newMasterPassword);
      return;
    }

    await this.unlock(oldMasterPassword);
    this.requireUnlocked();

    await this.unwrapDekWithKek(this.sessionKekOrThrow(), true);

    const saltB64 = this.enc.generateSaltB64();
    const rounds = SLS_CONSTANTS.ARGON2.ITERATIONS;
    const newKek = await deriveKekFromPassword(newMasterPassword, base64ToBytes(saltB64), rounds);
    const { ivWrap, wrappedKey } = await this.enc.wrapDek(this.dek!, newKek);

    this.config!.header = {
      v: SLS_CONSTANTS.CURRENT_DATA_VERSION,
      salt: saltB64,
      rounds,
      iv: ivWrap,
      wrappedKey
    };

    this.session.set(newKek, saltB64, rounds);
    this.dek = await this.enc.unwrapDek(ivWrap, wrappedKey, newKek, false);

    this.persist();
  }

  /** Lock the session (clears derived KEK & DEK from memory). */
  lock(): void {
    this.session.clear();
    this.dek = null;
  }

  /** Rotate DEK and device KEK. Allowed only in password-less mode. */
  async rotateKeys(): Promise<void> {
    await this.ready;
    this.requireConfig();
    if (this.isUsingMasterPassword()) {
      throw new ModeError("rotateKeys is allowed only in password-less mode");
    }
    const deviceKek = await DeviceKeyProvider.getKey(this.idbConfig);
    // Unwrap current DEK to read & re-encrypt data
    await this.unwrapDekWithKek(deviceKek, false);
    const plain = await this.enc.decryptData<Record<string, unknown>>(
      this.dek!,
      this.config!.data.iv,
      this.config!.data.ciphertext
    );

    // Generate new DEK and new device KEK, re-encrypt data
    const newDek = await this.enc.createDek();
    const { iv, ciphertext } = await this.enc.encryptData(newDek, plain);

    const newDeviceKek = await DeviceKeyProvider.rotateKey(this.idbConfig);
    const { ivWrap, wrappedKey } = await this.enc.wrapDek(newDek, newDeviceKek);

    this.config!.header = {
      v: SLS_CONSTANTS.CURRENT_DATA_VERSION,
      salt: "",
      rounds: 1,
      iv: ivWrap,
      wrappedKey
    };
    this.config!.data = { iv, ciphertext };

    // Keep session convenient (unwrapped in memory)
    this.dek = await this.enc.unwrapDek(ivWrap, wrappedKey, newDeviceKek, false);

    // Clear plaintext copy
    for (const k of Object.keys(plain)) (plain as Record<string, unknown>)[k] = null;

    this.persist();
  }

  /** Get decrypted data as a wipeable view object. */
  async getData<T extends Record<string, unknown> = Record<string, unknown>>(): Promise<SecureDataView<T>> {
    await this.ready;
    this.requireConfig();
    await this.ensureDekLoaded();
    if (!this.config!.data.iv || !this.config!.data.ciphertext) {
      // empty object
      return makeSecureDataView({} as T);
    }
    const obj = await this.enc.decryptData<unknown>(this.dek!, this.config!.data.iv, this.config!.data.ciphertext);
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

  /** Replace data with the provided plain object. */
  async setData<T extends Record<string, unknown>>(value: T): Promise<void> {
    await this.ready;
    this.requireConfig();
    await this.ensureDekLoaded();

    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new ValidationError("Data must be a plain object");
    }

    const plain = toPlainJson(value);
    const { iv, ciphertext } = await this.enc.encryptData(this.dek!, plain);
    this.config!.data = { iv, ciphertext };
    this.persist();
  }

  /**
   * Export the encrypted bundle as JSON string.
   * - If `customExportPassword` provided: derive export KEK (Argon2id) and rewrap DEK accordingly (mPw=false).
   * - If absent and in master mode: exports current config wrapped with master password (mPw=true).
   */
  async exportData(customExportPassword?: string): Promise<string> {
    await this.ready;
    this.requireConfig();

    if (!customExportPassword && this.isUsingMasterPassword()) {
      const copy = structuredClone(this.config!);
      copy.header.mPw = true;
      return JSON.stringify(copy);
    }

    if (!customExportPassword && !this.isUsingMasterPassword()) {
      throw new ExportError("Export password required in device mode");
    }

    if (customExportPassword !== undefined &&
        (typeof customExportPassword !== "string" || customExportPassword.trim().length === 0)) {
      throw new ExportError("Export password must be a non-empty string");
    }

    try {
      // Re-wrap DEK with export KEK
      const exportSaltB64 = this.enc.generateSaltB64();
      const exportKek = await deriveKekFromPassword(customExportPassword!, base64ToBytes(exportSaltB64));

      // Unwrap current DEK for wrapping using active KEK
      if (this.isUsingMasterPassword()) {
        await this.unwrapDekWithKek(this.sessionKekOrThrow(), true);
      } else {
        const deviceKek = await DeviceKeyProvider.getKey(this.idbConfig);
        await this.unwrapDekWithKek(deviceKek, true);
      }

      const { ivWrap, wrappedKey } = await this.enc.wrapDek(this.dek!, exportKek);
      const bundle: PersistedConfigV2 = {
        header: {
          v: SLS_CONSTANTS.CURRENT_DATA_VERSION,
          salt: exportSaltB64,
          rounds: SLS_CONSTANTS.ARGON2.ITERATIONS,
          iv: ivWrap,
          wrappedKey,
          mPw: false
        },
        data: this.config!.data
      };
      return JSON.stringify(bundle);
    } catch (e) {
      throw new ExportError((e as Error)?.message ?? "Export failed");
    }
  }

  /**
   * Import previously exported JSON.
   * - If bundle.mPw===true OR header.rounds>1 and no mPw flag: expects master password.
   * - Else expects export password.
   * After import, rewrap to device mode if using export password.
   */
  async importData(serialized: string, password?: string): Promise<string> {
    await this.ready;
    let bundle: PersistedConfigV2;
    try {
      bundle = JSON.parse(serialized) as PersistedConfigV2;
    } catch {
      throw new ImportError("Invalid import JSON");
    }

    if (bundle.header.v !== SLS_CONSTANTS.CURRENT_DATA_VERSION) {
      throw new ImportError(`Unsupported export version ${bundle.header.v}`);
    }

    this.validateBundle(bundle);

    const isMasterProtected =
      bundle.header.mPw === true ||
      (bundle.header.rounds > 1 && bundle.header.mPw !== false);

    if (typeof password !== "string" || password.length === 0) {
      throw new ImportError(isMasterProtected
        ? "Master password required to import"
        : "Export password required to import"
      );
    }

    if (isMasterProtected) {
      try {
        const kek = await deriveKekFromPassword(password, base64ToBytes(bundle.header.salt), bundle.header.rounds);
        await this.enc.unwrapDek(bundle.header.iv, bundle.header.wrappedKey, kek, false);
      } catch {
        throw new ImportError("Invalid master password or corrupted export data");
      }
      // Accept bundle as-is (master mode)
      this.config = bundle;
      this.dek = null; // locked until unlock()
      this.session.clear();
      this.persist();
      return 'masterPassword';
    }

    try {
      const exportKek = await deriveKekFromPassword(password, base64ToBytes(bundle.header.salt), bundle.header.rounds);
      const extractableDek = await this.enc.unwrapDek(bundle.header.iv, bundle.header.wrappedKey, exportKek, true);
      const deviceKek = await DeviceKeyProvider.getKey(this.idbConfig);
      const { ivWrap, wrappedKey } = await this.enc.wrapDek(extractableDek, deviceKek);

      // Store bundle in device mode
      this.config = {
        header: {
          v: SLS_CONSTANTS.CURRENT_DATA_VERSION,
          salt: "",
          rounds: 1,
          iv: ivWrap,
          wrappedKey
        },
        data: bundle.data
      };
      // Keep session unlocked for convenience
      this.dek = await this.enc.unwrapDek(ivWrap, wrappedKey, deviceKek, false);
      this.session.clear();
      this.persist();
      return 'customExportPassword'
    } catch (e) {
      throw new ImportError("Invalid export password or corrupted export data");
    }
  }

  /** Clear all data (localStorage + IndexedDB KEK) and reinitialize fresh empty store in device mode. */
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
    const isValidConfig = (cfg: PersistedConfigV2 | null): cfg is PersistedConfigV2 => {
      if (!cfg) return false;
      const h = cfg.header;
      const d = cfg.data;
      if (!h || h.v !== SLS_CONSTANTS.CURRENT_DATA_VERSION) return false;
      if (typeof h.rounds !== "number" || h.rounds < 1) return false;
      if (typeof h.iv !== "string" || typeof h.wrappedKey !== "string") return false;
      if (!d || typeof d.iv !== "string" || typeof d.ciphertext !== "string") return false;

      if (h.rounds === 1) {
        if (h.salt !== "") return false;
      } else {
        if (typeof h.salt !== "string" || h.salt.length === 0) return false;
      }

      try {
        base64ToBytes(h.iv);
        base64ToBytes(h.wrappedKey);
        if (d.iv) base64ToBytes(d.iv);
        if (d.ciphertext) base64ToBytes(d.ciphertext);
      } catch {
        return false;
      }
      return true;
    };

    // If we are forced fresh, build a new device-mode store immediately.
    if (forceFresh) {
      const dek = await this.enc.createDek();
      const deviceKek = await DeviceKeyProvider.getKey(this.idbConfig);
      const { ivWrap, wrappedKey } = await this.enc.wrapDek(dek, deviceKek);
      const unwrappedDek = await this.enc.unwrapDek(ivWrap, wrappedKey, deviceKek, false);
      const { iv, ciphertext } = await this.enc.encryptData(unwrappedDek, {}); // empty object

      this.config = {
        header: {
          v: SLS_CONSTANTS.CURRENT_DATA_VERSION,
          salt: "",
          rounds: 1,
          iv: ivWrap,
          wrappedKey
        },
        data: { iv, ciphertext }
      };
      this.dek = unwrappedDek;
      this.persist();
      return;
    }

    const existing = this.store.get();
    if (!isValidConfig(existing)) {
      await this.initialize(true);
      return;
    }

    this.config = existing;

    // Auto-unlock in device mode
    if (!this.isUsingMasterPassword()) {
      const deviceKek = await DeviceKeyProvider.getKey(this.idbConfig);
      try {
        this.dek = await this.enc.unwrapDek(existing.header.iv, existing.header.wrappedKey, deviceKek, false);
      } catch {
        // throw new ValidationError("Failed to unwrap DEK using device key. Tampered data?");
        // Cannot unwrap with current device KEK -> start fresh
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
    const { salt, rounds } = this.config!.header;
    const kek = this.session.match(salt, rounds);
    if (!kek) throw new LockedError("Session locked.");
    return kek;
  }

  private async ensureDekLoaded(): Promise<void> {
    if (this.dek) return;
    if (this.isUsingMasterPassword()) {
      const kek = this.sessionKekOrThrow();
      await this.unwrapDekWithKek(kek, false);
    } else {
      const deviceKek = await DeviceKeyProvider.getKey(this.idbConfig);
      await this.unwrapDekWithKek(deviceKek, false);
    }
  }

  private async unwrapDekWithKek(kek: CryptoKey, forWrapping: boolean): Promise<void> {
    this.dek = await this.enc.unwrapDek(this.config!.header.iv, this.config!.header.wrappedKey, kek, forWrapping);
  }

  private validateBundle(bundle: PersistedConfigV2): void {
    const h = bundle?.header as PersistedConfigV2["header"];
    const d = bundle?.data as PersistedConfigV2["data"];
    if (!h || !d) throw new ImportError("Invalid export structure");

    // header types
    if (typeof h.iv !== "string" || h.iv.length === 0) throw new ImportError("Invalid header.iv");
    if (typeof h.wrappedKey !== "string" || h.wrappedKey.length === 0) throw new ImportError("Invalid header.wrappedKey");
    if (!Number.isInteger(h.rounds) || h.rounds < 1) throw new ImportError("Invalid header.rounds");

    // rounds/salt semantics
    if (h.rounds === 1) {
      if (h.salt !== "") throw new ImportError("Device-mode bundles must have empty salt");
    } else {
      if (typeof h.salt !== "string" || h.salt.length === 0) {
        throw new ImportError("Password-protected bundles must include non-empty salt");
      }
    }

    // optional marker type
    if ("mPw" in h && typeof h.mPw !== "boolean") {
      throw new ImportError("Invalid header.mPw");
    }

    // data types
    if (typeof d.iv !== "string" || typeof d.ciphertext !== "string") {
      throw new ImportError("Invalid data section");
    }

    // base64 validation for all relevant fields
    try {
      base64ToBytes(h.iv);
      base64ToBytes(h.wrappedKey);
      if (d.iv) base64ToBytes(d.iv);
      if (d.ciphertext) base64ToBytes(d.ciphertext);
    } catch (e) {
      throw new ImportError("Invalid base64 data");
    }

  }
}