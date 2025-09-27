import "./../setup";
import { DeviceKeyProvider } from "../../src/crypto/DeviceKeyProvider";
import secureLocalStorage from "../../src";

describe("DeviceKeyProvider", () => {
  it("falls back to in-memory key when indexedDB is missing", async () => {
    await DeviceKeyProvider.deletePersistent();
    const original = (globalThis as unknown as { indexedDB?: IDBFactory }).indexedDB;
    // Remove the property so `"indexedDB" in globalThis` becomes false
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    delete (globalThis as any).indexedDB;

    const k1 = await DeviceKeyProvider.getKey();
    const k2 = await DeviceKeyProvider.getKey();
    expect(k1).toBe(k2); // stable memory fallback

    // Restore
    (globalThis as unknown as { indexedDB?: IDBFactory }).indexedDB = original;
  });

  it("returns stable key and updates on rotateKey()", async () => {
    await DeviceKeyProvider.deletePersistent();
    const a = await DeviceKeyProvider.getKey();
    const b = await DeviceKeyProvider.getKey();
    expect(a).toBe(b); // stable across calls

    const rotated = await DeviceKeyProvider.rotateKey();
    const c = await DeviceKeyProvider.getKey();

    expect(c).toBe(rotated);
    expect(c === b).toBe(false); // actually rotated
  });
});

describe("DeviceKeyProvider – idbConfig plumbing & isolation", () => {
  const cfgA = { dbName: "SLS_KEYS_A", storeName: "keysA", keyId: "deviceKek_v1_A" };
  const cfgB = { dbName: "SLS_KEYS_B", storeName: "keysB", keyId: "deviceKek_v1_B" };

  beforeEach(async () => {
    // Ensure clean slate (both configs) and reset spies between tests
    await DeviceKeyProvider.deletePersistent(cfgA);
    await DeviceKeyProvider.deletePersistent(cfgB);
    jest.restoreAllMocks();
  });

  it("forwards idbConfig through SecureLocalStorage.initialize() -> DeviceKeyProvider.getKey()", async () => {
    const spyGet = jest.spyOn(DeviceKeyProvider, "getKey");

    const sls = secureLocalStorage({
      storageKey: "test:plumb:init",
      idbConfig: cfgA
    });

    // trigger initialization + first write to ensure getKey is used along the path
    await sls.setData({ foo: 1 });

    // At least one call should include our cfgA fields
    const sawCfg = spyGet.mock.calls.some((args) => {
      const p = (args[0] ?? {}) as Partial<{ dbName: string; storeName: string; keyId: string }>;
      return p.dbName === cfgA.dbName && p.storeName === cfgA.storeName && p.keyId === cfgA.keyId;
    });
    expect(sawCfg).toBe(true);
  });

  it("forwards idbConfig to rotateKeys() -> DeviceKeyProvider.rotateKey()", async () => {
    const spyRotate = jest.spyOn(DeviceKeyProvider, "rotateKey");

    const sls = secureLocalStorage({
      storageKey: "test:plumb:rotate",
      idbConfig: cfgA
    });

    await sls.setData({ v: 1 });
    await sls.rotateKeys(); // device mode only; uses DeviceKeyProvider.rotateKey under the hood

    const sawCfg = spyRotate.mock.calls.some((args) => {
      const p = (args[0] ?? {}) as Partial<{ dbName: string; storeName: string; keyId: string }>;
      return p.dbName === cfgA.dbName && p.storeName === cfgA.storeName && p.keyId === cfgA.keyId;
    });
    expect(sawCfg).toBe(true);
  });

  it("forwards idbConfig to clear() -> DeviceKeyProvider.deletePersistent()", async () => {
    const spyDel = jest.spyOn(DeviceKeyProvider, "deletePersistent");

    const sls = secureLocalStorage({
      storageKey: "test:plumb:clear",
      idbConfig: cfgB
    });

    await sls.setData({ v: 1 });
    await sls.clear();

    const sawCfg = spyDel.mock.calls.some((args) => {
      const p = (args[0] ?? {}) as Partial<{ dbName: string; storeName: string; keyId: string }>;
      return p.dbName === cfgB.dbName && p.storeName === cfgB.storeName && p.keyId === cfgB.keyId;
    });
    expect(sawCfg).toBe(true);
  });

  it("maintains independent in-memory keys per idbConfig (A vs B) and rotates only the targeted one", async () => {
    // Fresh keys per config
    const a1 = await DeviceKeyProvider.getKey(cfgA);
    const a2 = await DeviceKeyProvider.getKey(cfgA);
    const b1 = await DeviceKeyProvider.getKey(cfgB);

    // Same cfg -> same in-memory key instance
    expect(a1).toBe(a2);

    // Different cfg -> different in-memory keys
    expect(a1 === b1).toBe(false);

    // Rotate only A; B should remain the same
    const aRot = await DeviceKeyProvider.rotateKey(cfgA);
    const a3 = await DeviceKeyProvider.getKey(cfgA);
    const b2 = await DeviceKeyProvider.getKey(cfgB);

    expect(aRot).toBe(a3);
    expect(a3 === a1).toBe(false); // actually rotated
    expect(b2).toBe(b1);           // untouched
  });
});