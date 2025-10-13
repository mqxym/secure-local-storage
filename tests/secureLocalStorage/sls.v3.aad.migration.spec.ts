import "../setup";
import secureLocalStorage from "../../src";
import { StorageService } from "../../src/storage/StorageService";
import { EncryptionManager } from "../../src/crypto/EncryptionManager";
import { DeviceKeyProvider } from "../../src/crypto/DeviceKeyProvider";
import { SLS_CONSTANTS } from "../../src/constants";
import { base64ToBytes } from "../../src/utils/base64";
import { deriveKekFromPassword } from "../../src/crypto/KeyDerivation";
import { LockedError } from "../../src/errors";

describe("v3 AAD migration", () => {
  it("device-mode: v2 store migrates to v3 immediately", async () => {
    const storageKey = "test:v3:migrate:device";
    const svc = new StorageService(storageKey);
    const enc = new EncryptionManager();

    // Build a v2 device-mode bundle manually (no AAD)
    const dek = await enc.createDek();
    const deviceKek = await DeviceKeyProvider.getKey();
    const { ivWrap, wrappedKey } = await enc.wrapDek(dek, deviceKek, undefined);
    const { iv, ciphertext } = await enc.encryptData(dek, { a: 1 }, undefined);

    svc.set({
      header: { v: 2, salt: "", rounds: 1, iv: ivWrap, wrappedKey },
      data: { iv, ciphertext }
    } as any);

    const sls = secureLocalStorage({ storageKey });
    const view = await sls.getData<{ a: number }>();
    expect(view.a).toBe(1);
    view.clear();

    // After first access, the store should be v3 with ctx:"store"
    const after = svc.get()!;
    expect(after.header.v).toBe(3);
    // @ts-ignore
    expect(after.header.ctx).toBe("store");
  });

  it("master-mode: v2 store migrates to v3 on unlock()", async () => {
    const storageKey = "test:v3:migrate:master";
    const svc = new StorageService(storageKey);
    const enc = new EncryptionManager();

    // Build a v2 master bundle manually (no AAD)
    const pw = "migrate-1";
    const saltB64 = enc.generateSaltB64();
    const kek = await deriveKekFromPassword(pw, base64ToBytes(saltB64));
    const dek = await enc.createDek();
    const { ivWrap, wrappedKey } = await enc.wrapDek(dek, kek, undefined);
    const { iv, ciphertext } = await enc.encryptData(dek, { b: 2 }, undefined);

    svc.set({
      header: { v: 2, salt: saltB64, rounds: SLS_CONSTANTS.ARGON2.ITERATIONS, iv: ivWrap, wrappedKey },
      data: { iv, ciphertext }
    } as any);

    const sls = secureLocalStorage({ storageKey });
    // locked before unlock
    await expect(sls.getData()).rejects.toBeInstanceOf(LockedError);

    await sls.unlock(pw);
    const view = await sls.getData<{ b: number }>();
    expect(view.b).toBe(2);
    view.clear();

    const after = svc.get()!;
    expect(after.header.v).toBe(3);
    // @ts-ignore
    expect(after.header.ctx).toBe("store");
  });
});