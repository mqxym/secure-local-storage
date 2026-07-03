import "./../setup";
import { DeviceKeyProvider } from "../../src/crypto/DeviceKeyProvider";

describe("DeviceKeyProvider - concurrency (single-flight)", () => {
  const cfg = { dbName: "SLS_KEYS_CONC", storeName: "keysConc", keyId: "deviceKek_v1_conc" };

  beforeEach(async () => {
    await DeviceKeyProvider.deletePersistent(cfg);
    jest.restoreAllMocks();
  });

  afterEach(async () => {
    await DeviceKeyProvider.deletePersistent(cfg);
    jest.restoreAllMocks();
  });

  it("concurrent getKey() calls resolve to the same key instance and generate it once", async () => {
    const genSpy = jest.spyOn(crypto.subtle, "generateKey");

    const results = await Promise.all([
      DeviceKeyProvider.getKey(cfg),
      DeviceKeyProvider.getKey(cfg),
      DeviceKeyProvider.getKey(cfg),
      DeviceKeyProvider.getKey(cfg),
      DeviceKeyProvider.getKey(cfg)
    ]);

    const [first] = results;
    for (const k of results) expect(k).toBe(first);

    // Single-flight: the device KEK must be generated at most once for the batch.
    const aesGenCalls = genSpy.mock.calls.filter((args) => {
      const algo = args[0] as { name?: string };
      return algo?.name === "AES-GCM";
    });
    expect(aesGenCalls.length).toBeLessThanOrEqual(1);
  });

  it("rotateKey() replaces the cached key returned by subsequent getKey()", async () => {
    const before = await DeviceKeyProvider.getKey(cfg);
    const rotated = await DeviceKeyProvider.rotateKey(cfg);
    const after = await DeviceKeyProvider.getKey(cfg);

    expect(after).toBe(rotated);
    expect(after === before).toBe(false);
  });
});
