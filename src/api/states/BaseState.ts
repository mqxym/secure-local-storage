import type { SecureLocalStorage } from "../SecureLocalStorageStates";

export abstract class State {
  constructor(protected context: SecureLocalStorage) {}

  abstract isUsingMasterPassword(): boolean;
  abstract isLocked(): boolean;
  abstract unlock(masterPassword: string): Promise<void>;
  abstract setMasterPassword(masterPassword: string): Promise<void>;
  abstract removeMasterPassword(): Promise<void>;
  abstract rotateMasterPassword(oldMasterPassword: string, newMasterPassword: string): Promise<void>;
  abstract lock(): void;
  abstract rotateKeys(): Promise<void>;
  abstract getData<T extends Record<string, unknown>>(): Promise<any>;
  abstract setData<T extends Record<string, unknown>>(value: T): Promise<void>;
  abstract exportData(customExportPassword?: string): Promise<string>;
  abstract importData(serialized: string, password?: string): Promise<string>;
  abstract clear(): Promise<void>;
  abstract initialize(forceFresh?: boolean): Promise<void>;

  protected transitionTo(state: State): void {
    this.context.transitionTo(state);
  }
}