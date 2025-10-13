import { State } from "./BaseState";
import { MasterPasswordState } from "./MasterPasswordState";
import { InitialState } from "./InitialState";
import { ValidationError, LockedError } from "../../errors";
import { base64ToBytes } from "../../utils/base64";

export class LockedState extends State {
  isUsingMasterPassword(): boolean {
    return true;
  }

  isLocked(): boolean {
    return true;
  }

  async unlock(masterPassword: string): Promise<void> {
    if (!this.context.config) return;

    if (typeof masterPassword !== "string" || masterPassword.trim().length === 0) {
      throw new ValidationError("masterPassword must be a non-empty string");
    }

    const { salt, rounds } = this.context.config.header;
    const kek = await this.context.deriveKekFromPassword(masterPassword, base64ToBytes(salt), rounds);

    try {
      this.context.session.set(kek, salt, rounds);
      await this.context.unwrapDekWithKek(kek, false, this.context.versionManager.getAadFor("wrap", this.context.config));
    } catch {
      this.context.session.clear();
      throw new ValidationError("Invalid master password");
    }

    if (this.context.versionManager.isV2(this.context.config)) {
      await this.context.migrateV2ToV3("master", this.context.config, kek);
    }
    this.transitionTo(new MasterPasswordState(this.context));
  }

  async setMasterPassword(masterPassword: string): Promise<void> {
    throw new LockedError();
  }

  async removeMasterPassword(): Promise<void> {
    throw new LockedError();
  }

  async rotateMasterPassword(oldMasterPassword: string, newMasterPassword: string): Promise<void> {
    await this.unlock(oldMasterPassword);
    // The state will be changed to MasterPasswordState, so we can call rotateMasterPassword on it
    await this.context.rotateMasterPassword(oldMasterPassword, newMasterPassword);
  }

  lock(): void {
    // No-op
  }

  async rotateKeys(): Promise<void> {
    throw new LockedError();
  }

  async getData<T extends Record<string, unknown>>(): Promise<any> {
    throw new LockedError();
  }

  async setData<T extends Record<string, unknown>>(value: T): Promise<void> {
    throw new LockedError();
  }

  async exportData(_customExportPassword?: string): Promise<string> {
    throw new LockedError();
  }

  importData(serialized: string, password?: string): Promise<string> {
    throw new Error("Method not implemented.");
  }
  clear(): Promise<void> {
    return (async () => {
      this.context.session.clear();
      this.context.dek = null;
      this.context.store.clear();
      await this.context.deviceKeyProvider.deletePersistent(this.context.idbConfig);
      await new InitialState(this.context).initialize(true);
    })();
  }
  initialize(forceFresh?: boolean): Promise<void> {
    throw new Error("Method not implemented.");
  }
}