import { State } from "./BaseState";
import { MasterPasswordState } from "./MasterPasswordState";
import { ModeError, ValidationError } from "../../errors";
import { SLS_CONSTANTS } from "../../constants";
import { base64ToBytes } from "../../utils/base64";
import { toPlainJson } from "../../utils/json";
import { makeSecureDataView, SecureDataView } from "../../utils/secureDataView";
import type { PersistedConfigV3 } from "../../types";

export class DeviceModeState extends State {
  isUsingMasterPassword(): boolean {
    return false;
  }

  isLocked(): boolean {
    return false;
  }

  async unlock(masterPassword: string): Promise<void> {
    // No-op in device mode
  }

  async setMasterPassword(masterPassword: string): Promise<void> {
    this.context.requireConfig();
    const pw = typeof masterPassword === "string" ? masterPassword.trim() : "";
    if (pw.length === 0) {
      throw new ValidationError("masterPassword must be a non-empty string");
    }

    const deviceKek = await this.context.deviceKeyProvider.getKey(this.context.idbConfig);
    await this.context.unwrapDekWithKek(deviceKek, true, this.context.versionManager.getAadFor("wrap", this.context.config!));

    const plain = await this.context.decryptCurrentData();

    const saltB64 = this.context.enc.generateSaltB64();
    const rounds = SLS_CONSTANTS.ARGON2.ITERATIONS;
    const kek = await this.context.deriveKekFromPassword(masterPassword, base64ToBytes(saltB64), rounds);

    const ctx: PersistedConfigV3["header"]["ctx"] = "store";
    const wrapAad = this.context.versionManager.buildWrapAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION);
    const wrapped = await this.context.enc.wrapDek(this.context.dek!, kek, wrapAad);

    const dataAad = this.context.versionManager.buildDataAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION, wrapped.ivWrap, wrapped.wrappedKey);
    const { iv, ciphertext } = await this.context.enc.encryptData(this.context.dek!, plain, dataAad);

    this.context.config = {
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

    this.context.session.set(kek, saltB64, rounds);
    this.context.dek = await this.context.enc.unwrapDek(wrapped.ivWrap, wrapped.wrappedKey, kek, false, wrapAad);
    this.context.persist();
    this.transitionTo(new MasterPasswordState(this.context));
  }

  async removeMasterPassword(): Promise<void> {
    throw new ModeError("No master password is set");
  }

  async rotateMasterPassword(oldMasterPassword: string, newMasterPassword: string): Promise<void> {
    const newPw = typeof newMasterPassword === "string" ? newMasterPassword.trim() : "";
    if (newPw.length === 0) {
      throw new ValidationError("newMasterPassword must be a non-empty string");
    }
    await this.setMasterPassword(newMasterPassword);
  }

  lock(): void {
    // No-op
  }

  async rotateKeys(): Promise<void> {
    this.context.requireConfig();
    const deviceKek = await this.context.deviceKeyProvider.getKey(this.context.idbConfig);

    await this.context.unwrapDekWithKek(deviceKek, false, this.context.versionManager.getAadFor("wrap", this.context.config!));
    const plain = await this.context.decryptCurrentData();

    const newDek = await this.context.enc.createDek();

    const newDeviceKek = await this.context.deviceKeyProvider.rotateKey(this.context.idbConfig);
    const ctx: PersistedConfigV3["header"]["ctx"] = "store";
    const wrapAad = this.context.versionManager.buildWrapAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION);
    const { ivWrap, wrappedKey } = await this.context.enc.wrapDek(newDek, newDeviceKek, wrapAad);

    const dataAad = this.context.versionManager.buildDataAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION, ivWrap, wrappedKey);
    const { iv, ciphertext } = await this.context.enc.encryptData(newDek, plain, dataAad);

    this.context.config = {
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

    this.context.dek = await this.context.enc.unwrapDek(ivWrap, wrappedKey, newDeviceKek, false, wrapAad);
    for (const k of Object.keys(plain)) (plain as Record<string, unknown>)[k] = null;
    this.context.persist();
  }

  async getData<T extends Record<string, unknown>>(): Promise<SecureDataView<T>> {
    this.context.requireConfig();
    await this.context.ensureDekLoaded();
    if (!this.context.config!.data.iv || !this.context.config!.data.ciphertext) {
      return makeSecureDataView({} as T);
    }

    const dataAad = this.context.versionManager.getAadFor("data", this.context.config);
    const obj = await this.context.enc.decryptData<unknown>(this.context.dek!, this.context.config!.data.iv, this.context.config!.data.ciphertext, dataAad);

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

  async setData<T extends Record<string, unknown>>(value: T): Promise<void> {
    this.context.requireConfig();
    await this.context.ensureDekLoaded();

    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new ValidationError("Data must be a plain object");
    }

    const plain = toPlainJson(value);
    const dataAad = this.context.versionManager.getAadFor("data", this.context.config);
    const { iv, ciphertext } = await this.context.enc.encryptData(this.context.dek!, plain, dataAad);
    this.context.config!.data = { iv, ciphertext };
    this.context.persist();
  }

  exportData(customExportPassword?: string): Promise<string> {
    throw new Error("Method not implemented.");
  }
  importData(serialized: string, password?: string): Promise<string> {
    throw new Error("Method not implemented.");
  }
  clear(): Promise<void> {
    throw new Error("Method not implemented.");
  }
  initialize(forceFresh?: boolean): Promise<void> {
    throw new Error("Method not implemented.");
  }
}