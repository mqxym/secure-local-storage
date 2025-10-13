import { State } from "./BaseState";
import { DeviceModeState } from "./DeviceModeState";
import { LockedState } from "./LockedState";
import { ModeError, ValidationError } from "../../errors";
import { SLS_CONSTANTS } from "../../constants";
import { base64ToBytes } from "../../utils/base64";
import { toPlainJson } from "../../utils/json";
import { makeSecureDataView, SecureDataView } from "../../utils/secureDataView";
import type { PersistedConfigV3 } from "../../types";

export class MasterPasswordState extends State {
  isUsingMasterPassword(): boolean {
    return true;
  }

  isLocked(): boolean {
    return false;
  }

  async unlock(masterPassword: string): Promise<void> {
    // No-op, already unlocked
  }

  async setMasterPassword(masterPassword: string): Promise<void> {
    throw new ModeError("Master password already set; use rotateMasterPassword()");
  }

  async removeMasterPassword(): Promise<void> {
    this.context.requireConfig();
    this.context.requireUnlocked();

    await this.context.unwrapDekWithKek(this.context.sessionKekOrThrow(), true, this.context.versionManager.getAadFor("wrap", this.context.config!));

    const plain = await this.context.decryptCurrentData();

    const deviceKek = await this.context.deviceKeyProvider.getKey(this.context.idbConfig);

    const ctx: PersistedConfigV3["header"]["ctx"] = "store";
    const wrapAad = this.context.versionManager.buildWrapAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION);
    const { ivWrap, wrappedKey } = await this.context.enc.wrapDek(this.context.dek!, deviceKek, wrapAad);

    const dataAad = this.context.versionManager.buildDataAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION, ivWrap, wrappedKey);
    const { iv, ciphertext } = await this.context.enc.encryptData(this.context.dek!, plain, dataAad);

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

    this.context.dek = await this.context.enc.unwrapDek(ivWrap, wrappedKey, deviceKek, false, wrapAad);
    this.context.session.clear();
    this.context.persist();
    this.transitionTo(new DeviceModeState(this.context));
  }

  async rotateMasterPassword(oldMasterPassword: string, newMasterPassword: string): Promise<void> {
    this.context.requireConfig();

    const newPw = typeof newMasterPassword === "string" ? newMasterPassword.trim() : "";
    if (newPw.length === 0) {
      throw new ValidationError("newMasterPassword must be a non-empty string");
    }

    // This is a bit of a hack, but it's the simplest way to verify the old password
    await this.context.unlock(oldMasterPassword);

    await this.context.unwrapDekWithKek(this.context.sessionKekOrThrow(), true, this.context.versionManager.getAadFor("wrap", this.context.config!));
    const plain = await this.context.decryptCurrentData();

    const saltB64 = this.context.enc.generateSaltB64();
    const rounds = SLS_CONSTANTS.ARGON2.ITERATIONS;
    const newKek = await this.context.deriveKekFromPassword(newMasterPassword, base64ToBytes(saltB64), rounds);

    const ctx: PersistedConfigV3["header"]["ctx"] = "store";
    const wrapAad = this.context.versionManager.buildWrapAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION);
    const { ivWrap, wrappedKey } = await this.context.enc.wrapDek(this.context.dek!, newKek, wrapAad);

    const dataAad = this.context.versionManager.buildDataAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION, ivWrap, wrappedKey);
    const { iv, ciphertext } = await this.context.enc.encryptData(this.context.dek!, plain, dataAad);

    this.context.config = {
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

    this.context.session.set(newKek, saltB64, rounds);
    this.context.dek = await this.context.enc.unwrapDek(ivWrap, wrappedKey, newKek, false, wrapAad);

    this.context.persist();
  }

  lock(): void {
    this.context.session.clear();
    this.context.dek = null;
    this.transitionTo(new LockedState(this.context));
  }

  async rotateKeys(): Promise<void> {
    throw new ModeError("rotateKeys is allowed only in password-less mode");
  }

  async getData<T extends Record<string, unknown>>(): Promise<SecureDataView<T>> {
    this.context.requireConfig();
    this.context.requireUnlocked();
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
    this.context.requireUnlocked();

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