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

    // Build AAD (only for v3); v2 uses undefined (no AAD)
    const te = new TextEncoder();
    const wrapAad =
      cfg.header.v === 3
        ? te.encode(`sls|wrap|v${cfg.header.v}|${storageKey}`)
        : undefined;

    const dek = await enc.unwrapDek(cfg.header.iv, cfg.header.wrappedKey, deviceKek, false, wrapAad);

    // Data AAD must bind to the header (only for v3)
    const dataAad =
      cfg.header.v === 3
        ? te.encode(`sls|data|v${cfg.header.v}|${storageKey}|${cfg.header.iv}|${cfg.header.wrappedKey}`)
        : undefined;

    // Re-encrypt a non-object (string) and persist it
    const wrong = await enc.encryptData(dek, "not-object", dataAad);
    cfg.data = wrong;
    svc.set(cfg);

    // IMPORTANT: create a fresh instance so it reloads the mutated config
    const sls2 = secureLocalStorage({ storageKey });

    await expect(sls2.getData()).rejects.toBeInstanceOf(ValidationError);
  });
});