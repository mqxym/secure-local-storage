import "../setup";
import secureLocalStorage from "../../src";
import { StorageService } from "../../src/storage/StorageService";
import { EncryptionManager } from "../../src/crypto/EncryptionManager";
import { DeviceKeyProvider } from "../../src/crypto/DeviceKeyProvider";
import { CryptoError } from "../../src/errors";

/**
 * Ensures ciphertext is bound to the header via AAD:
 * If we change the wrap header (new iv/wrappedKey) but keep the data ciphertext,
 * decryption must fail in v3 because data AAD includes header fields.
 */
describe("v3 AAD binding prevents mix-and-match", () => {
  it("changing header while keeping data causes decrypt failure", async () => {
    const storageKey = "test:v3:aad:bind";
    const sls = secureLocalStorage({ storageKey });
    await sls.setData({ x: 7 });

    // Read persisted config
    const svc = new StorageService(storageKey);
    const cfg = svc.get()!;
    expect(cfg.header.v).toBe(3);

    // Tamper: swap the header to a fresh wrap (iv/wrappedKey) but leave data untouched
    const enc = new EncryptionManager();
    const deviceKek = await DeviceKeyProvider.getKey();

    const te = new TextEncoder();
    const wrapAad = te.encode(`sls|wrap|v3|${storageKey}`);
    const tmpDek = await enc.createDek();
    const wrappedNew = await enc.wrapDek(tmpDek, deviceKek, wrapAad);

    cfg.header.iv = wrappedNew.ivWrap;
    cfg.header.wrappedKey = wrappedNew.wrappedKey;
    // keep ctx:"store"
    // @ts-ignore
    cfg.header.ctx = "store";
    svc.set(cfg as any);

    // Now any getData should fail because data AAD uses header.iv/wrappedKey
    const sls2 = secureLocalStorage({ storageKey });
    await expect(sls2.getData()).rejects.toBeInstanceOf(CryptoError);
  });
});