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

export interface SecureLocalStorageOptions {
  storageKey?: string;
  idbConfig?: Partial<IdbConfig>;
}

export class SecureLocalStorage {
  private state: State;
  public readonly store: StorageService;
  public readonly enc = new EncryptionManager();
  public readonly session = new SessionKeyCache();
  public config: PersistedConfig | null = null;
  public dek: CryptoKey | null = null;
  private ready: Promise<void>;
  public readonly idbConfig: { dbName: string; storeName: string; keyId: string };
  public readonly storageKeyStr: string;
  public readonly versionManager: VersionManager;
  public lastResetReason: "invalid-config" | "device-kek-mismatch" | null = null;
  public readonly DATA_VERSION: number = SLS_CONSTANTS.CURRENT_DATA_VERSION;
  public readonly deviceKeyProvider = DeviceKeyProvider;
  public readonly deriveKekFromPassword = deriveKekFromPassword;

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

  public transitionTo(state: State): void {
    this.state = state;
  }

  public isUsingMasterPassword(): boolean {
    return this.state.isUsingMasterPassword();
  }

  public isLocked(): boolean {
    return this.state.isLocked();
  }

  public async unlock(masterPassword: string): Promise<void> {
    await this.ready;
    return this.state.unlock(masterPassword);
  }

  public async setMasterPassword(masterPassword: string): Promise<void> {
    await this.ready;
    return this.state.setMasterPassword(masterPassword);
  }

  public async removeMasterPassword(): Promise<void> {
    await this.ready;
    return this.state.removeMasterPassword();
  }

  public async rotateMasterPassword(oldMasterPassword: string, newMasterPassword: string): Promise<void> {
    await this.ready;
    return this.state.rotateMasterPassword(oldMasterPassword, newMasterPassword);
  }

  public lock(): void {
    this.state.lock();
  }

  public async rotateKeys(): Promise<void> {
    await this.ready;
    return this.state.rotateKeys();
  }

  public async getData<T extends Record<string, unknown> = Record<string, unknown>>(): Promise<SecureDataView<T>> {
    await this.ready;
    return this.state.getData();
  }

  public async setData<T extends Record<string, unknown>>(value: T): Promise<void> {
    await this.ready;
    return this.state.setData(value);
  }

  public async exportData(customExportPassword?: string): Promise<string> {
    await this.ready;
    return this.state.exportData(customExportPassword);
  }

  public async importData(serialized: string, password?: string): Promise<string> {
    await this.ready;
    let t: unknown;
 
    const { bundle, isMasterProtected } = Portability.parseAndClassify(serialized, SLS_CONSTANTS.SUPPORTED_VERSIONS);   

    this.validateBundle(bundle);

    if (typeof password !== "string" || password.length === 0) {
      throw new ImportError(isMasterProtected
        ? "Master password required to import"
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

  public async clear(): Promise<void> {
    await this.ready;
    return this.state.clear();
  }

  public persist(): void {
    this.store.set(this.config!);
  }

  public requireConfig(): void {
    if (!this.config) throw new ImportError("No configuration present");
  }

  public requireUnlocked(): void {
    if (!this.dek) throw new LockedError();
  }

  public sessionKekOrThrow(): CryptoKey {
    const { salt, rounds } = this.config!.header as any;
    const kek = this.session.match(salt, rounds);
    if (!kek) throw new LockedError("Session locked.");
    return kek;
  }

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

  public async unwrapDekWithKek(kek: CryptoKey, forWrapping: boolean, aad?: Uint8Array): Promise<void> {
    this.dek = await this.enc.unwrapDek(this.config!.header.iv, this.config!.header.wrappedKey, kek, forWrapping, aad);
  }

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

  public async decryptCurrentData(): Promise<Record<string, unknown>> {
    if (!this.config!.data.iv || !this.config!.data.ciphertext) return {};
    const aad = this.versionManager.getAadFor("data", this.config);
    return await this.enc.decryptData<Record<string, unknown>>(
      this.dek!, this.config!.data.iv, this.config!.data.ciphertext, aad
    );
  }

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