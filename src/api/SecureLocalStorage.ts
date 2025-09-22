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
import {
  CryptoError,
  ExportError,
  ImportError,
  LockedError,
  ModeError,
  ValidationError
} from "../errors";

export interface SecureLocalStorageOptions {
  /** Override the localStorage key (for multi-tenant apps or tests). */
  storageKey?: string;
}

export class SecureLocalStorage {
  private readonly store: StorageService;
  private readonly enc = new EncryptionManager();
  private readonly session = new SessionKeyCache();
  private config: PersistedConfigV2 | null = null;
  private dek: CryptoKey | null = null;
  private ready: Promise<void>;

  constructor(opts?: SecureLocalStorageOptions) {
    this.store = new StorageService(opts?.storageKey);
    this.ready = this.initialize();
  }

  // --------------------------- public API ---------------------------

  public isUsingMasterPassword(): boolean {
    return (this.config?.header.rounds ?? 1) > 1;
  }


  /** Unlock session with master password (no-op in device mode). */
  async unlock(masterPassword: string): Promise<void> {
    await this.ready;
    if (!this.config) throw new ImportError("No data to unlock");
    if (!this.isUsingMasterPassword()) return; // already unlocked in device mode

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
    const deviceKek = await DeviceKeyProvider.getKey();
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

    const deviceKek = await DeviceKeyProvider.getKey();
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
    await this.unlock(oldMasterPassword);
    await this.setMasterPassword(newMasterPassword);
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
    const deviceKek = await DeviceKeyProvider.getKey();
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

    const newDeviceKek = await DeviceKeyProvider.rotateKey();
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
    const obj = await this.enc.decryptData<T>(this.dek!, this.config!.data.iv, this.config!.data.ciphertext);
    return makeSecureDataView(obj);
  }

  /** Replace data with the provided plain object. */
  async setData<T extends Record<string, unknown>>(value: T): Promise<void> {
    await this.ready;
    this.requireConfig();
    await this.ensureDekLoaded();
    const plain = toPlainJson(value);
    const { iv, ciphertext } = await this.enc.encryptData(this.dek!, plain);
    this.config!.data = { iv, ciphertext };
    this.persist();
  }

  /**
   * Export the encrypted bundle as JSON string.
   * - If `customExportPassword` provided: derive export KEK (Argon2id) and rewrap DEK accordingly (mPw=false).
   * - If absent and in master mode: exports current config wrapped with master password (mPw=true).
   * - Requires unlocked session.
   */
  async exportData(customExportPassword?: string): Promise<string> {
    await this.ready;
    this.requireConfig();
    this.requireUnlocked();

    if (!customExportPassword && this.isUsingMasterPassword()) {
      const copy = structuredClone(this.config!);
      copy.header.mPw = true;
      return JSON.stringify(copy);
    }

    if (!customExportPassword && !this.isUsingMasterPassword()) {
      throw new ExportError("Export password required in device mode");
    }

    try {
      // Re-wrap DEK with export KEK
      const exportSaltB64 = this.enc.generateSaltB64();
      const exportKek = await deriveKekFromPassword(customExportPassword!, base64ToBytes(exportSaltB64));

      // Unwrap current DEK for wrapping using active KEK
      if (this.isUsingMasterPassword()) {
        await this.unwrapDekWithKek(this.sessionKekOrThrow(), true);
      } else {
        const deviceKek = await DeviceKeyProvider.getKey();
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
  async importData(serialized: string, password?: string): Promise<void> {
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

    const isMasterProtected = bundle.header.mPw === true || (bundle.header.rounds > 1 && bundle.header.mPw !== false);
    if (isMasterProtected) {
      if (!password) throw new ImportError("Master password required to import");
      // Validate master password by trying to unwrap
      const kek = await deriveKekFromPassword(password, base64ToBytes(bundle.header.salt), bundle.header.rounds);
      try {
        // test unwrap (non-extractable)
        await this.enc.unwrapDek(bundle.header.iv, bundle.header.wrappedKey, kek, false);
      } catch {
        throw new ImportError("Invalid master password");
      }
      // Accept bundle as-is (master mode)
      this.config = bundle;
      this.dek = null; // locked until unlock()
      this.session.clear();
      this.persist();
      return;
    }

    if (!password) throw new ImportError("Export password required to import");

    try {
      const exportKek = await deriveKekFromPassword(password, base64ToBytes(bundle.header.salt), bundle.header.rounds);
      const extractableDek = await this.enc.unwrapDek(bundle.header.iv, bundle.header.wrappedKey, exportKek, true);
      const deviceKek = await DeviceKeyProvider.getKey();
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
    await DeviceKeyProvider.deletePersistent();
    await this.initialize(true);
  }

  // --------------------------- private helpers ---------------------------

  private async initialize(forceFresh = false): Promise<void> {
    const isValidConfig = (cfg: PersistedConfigV2 | null): cfg is PersistedConfigV2 => {
      return !!cfg
        && cfg.header?.v === SLS_CONSTANTS.CURRENT_DATA_VERSION
        && typeof cfg.header.iv === "string"
        && typeof cfg.header.wrappedKey === "string"
        && typeof cfg.header.rounds === "number"
        && cfg.header.rounds >= 1
        && !!cfg.data
        && typeof cfg.data.iv === "string"
        && typeof cfg.data.ciphertext === "string";
    };

    // If we are forced fresh, build a new device-mode store immediately.
    if (forceFresh) {
      const dek = await this.enc.createDek();
      const deviceKek = await DeviceKeyProvider.getKey();
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
      const deviceKek = await DeviceKeyProvider.getKey();
      try {
        this.dek = await this.enc.unwrapDek(existing.header.iv, existing.header.wrappedKey, deviceKek, false);
      } catch {
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
      const deviceKek = await DeviceKeyProvider.getKey();
      await this.unwrapDekWithKek(deviceKek, false);
    }
  }

  private async unwrapDekWithKek(kek: CryptoKey, forWrapping: boolean): Promise<void> {
    this.dek = await this.enc.unwrapDek(this.config!.header.iv, this.config!.header.wrappedKey, kek, forWrapping);
  }
}