import "./setup";
import { DeviceKeyProvider } from "../src/crypto/DeviceKeyProvider";

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