import { State } from "./BaseState";
import { DeviceModeState } from "./DeviceModeState";
import { LockedState } from "./LockedState";
import type { PersistedConfigV3 } from "../../types";
import { SLS_CONSTANTS } from "../../constants";

export class InitialState extends State {
  async initialize(forceFresh = false): Promise<void> {
    if (forceFresh) {
      await this.createNewStore();
      return;
    }

    const existing = this.context.store.get();
    if (!this.context.versionManager.isValidConfig(existing)) {
      this.context.lastResetReason = "invalid-config";
      await this.createNewStore();
      return;
    }

    this.context.config = existing;

    if ((this.context.config?.header.rounds ?? 1) > 1) {
      this.transitionTo(new LockedState(this.context));
    } else {
      const deviceKek = await this.context.deviceKeyProvider.getKey(this.context.idbConfig);
      try {
        await this.context.unwrapDekWithKek(deviceKek, false, this.context.versionManager.getAadFor("wrap", existing));

        if (this.context.versionManager.isV2(existing)) {
          await this.context.migrateV2ToV3("device", existing, deviceKek);
        }
        this.transitionTo(new DeviceModeState(this.context));
      } catch {
        this.context.lastResetReason = "device-kek-mismatch";
        await this.createNewStore();
      }
    }
  }

  private async createNewStore(): Promise<void> {
    const dek = await this.context.enc.createDek();
    const deviceKek = await this.context.deviceKeyProvider.getKey(this.context.idbConfig);

    const ctx: PersistedConfigV3["header"]["ctx"] = "store";
    const wrapAad = this.context.versionManager.buildWrapAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION);
    const { ivWrap, wrappedKey } = await this.context.enc.wrapDek(dek, deviceKek, wrapAad);
    const unwrappedDek = await this.context.enc.unwrapDek(ivWrap, wrappedKey, deviceKek, false, wrapAad);

    const dataAad = this.context.versionManager.buildDataAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION, ivWrap, wrappedKey);
    const { iv, ciphertext } = await this.context.enc.encryptData(unwrappedDek, {}, dataAad);

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
    this.context.dek = unwrappedDek;
    this.context.persist();
    this.transitionTo(new DeviceModeState(this.context));
  }

  isUsingMasterPassword(): boolean { throw new Error("Not initialized"); }
  isLocked(): boolean { throw new Error("Not initialized"); }
  unlock(masterPassword: string): Promise<void> { throw new Error("Not initialized"); }
  setMasterPassword(masterPassword: string): Promise<void> { throw new Error("Not initialized"); }
  removeMasterPassword(): Promise<void> { throw new Error("Not initialized"); }
  rotateMasterPassword(oldMasterPassword: string, newMasterPassword: string): Promise<void> { throw new Error("Not initialized"); }
  lock(): void { throw new Error("Not initialized"); }
  rotateKeys(): Promise<void> { throw new Error("Not initialized"); }
  getData<T extends Record<string, unknown>>(): Promise<any> { throw new Error("Not initialized"); }
  setData<T extends Record<string, unknown>>(value: T): Promise<void> { throw new Error("Not initialized"); }
  exportData(customExportPassword?: string): Promise<string> { throw new Error("Not initialized"); }
  importData(serialized: string, password?: string): Promise<string> { throw new Error("Not initialized"); }
  async clear(): Promise<void> {
    this.context.session.clear();
    this.context.dek = null;
    this.context.store.clear();
    await this.context.deviceKeyProvider.deletePersistent(this.context.idbConfig);
    await this.initialize(true);
  }
}