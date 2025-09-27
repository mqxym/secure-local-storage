import "../setup";
import secureLocalStorage from "../../src";
import { DeviceKeyProvider } from "../../src/crypto/DeviceKeyProvider";
import { EncryptionManager } from "../../src/crypto/EncryptionManager";
import { StorageService } from "../../src/storage/StorageService";
import { ValidationError } from "../../src/errors";

describe("getData() rejects non-plain object payloads", () => {
  it("tampered ciphertext decrypts to a string -> ValidationError", async () => {
    const storageKey = "test:getData:plain";
    const sls = secureLocalStorage({ storageKey });
    await sls.setData({ ok: true });

    // Read and tamper the persisted bundle
    const svc = new StorageService(storageKey);
    const cfg = svc.get()!;
    const deviceKek = await DeviceKeyProvider.getKey();
    const enc = new EncryptionManager();
    const dek = await enc.unwrapDek(cfg.header.iv, cfg.header.wrappedKey, deviceKek, false);

    // Re-encrypt a non-object (string) and persist it
    const wrong = await enc.encryptData(dek, "not-object");
    cfg.data = wrong;
    svc.set(cfg);

    // IMPORTANT: create a fresh instance so it reloads the mutated config
    const sls2 = secureLocalStorage({ storageKey });

    await expect(sls2.getData()).rejects.toBeInstanceOf(ValidationError);
  });
});