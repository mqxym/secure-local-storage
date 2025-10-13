import { State } from "./BaseState";
export declare class LockedState extends State {
    isUsingMasterPassword(): boolean;
    isLocked(): boolean;
    unlock(masterPassword: string): Promise<void>;
    setMasterPassword(masterPassword: string): Promise<void>;
    removeMasterPassword(): Promise<void>;
    rotateMasterPassword(oldMasterPassword: string, newMasterPassword: string): Promise<void>;
    lock(): void;
    rotateKeys(): Promise<void>;
    getData<T extends Record<string, unknown>>(): Promise<any>;
    setData<T extends Record<string, unknown>>(value: T): Promise<void>;
    exportData(customExportPassword?: string): Promise<string>;
    importData(serialized: string, password?: string): Promise<string>;
    clear(): Promise<void>;
    initialize(forceFresh?: boolean): Promise<void>;
}
