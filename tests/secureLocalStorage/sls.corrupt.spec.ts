import "./../setup";
import secureLocalStorage from "../../src";
import { StorageService } from "../../src/storage/StorageService";
import { DeviceKeyProvider } from "../../src/crypto/DeviceKeyProvider";

describe("corruption / recovery paths", () => {
  it("treats missing data.iv/data.ciphertext as empty object", async () => {
    const storageKey = "test:corrupt:missing-data";
    // Create initial config
    const sls = secureLocalStorage({ storageKey });
    await sls.setData({ x: 1 });

    // Corrupt stored data: clear iv & ciphertext
    const svc = new StorageService(storageKey);
    const cfg = svc.get()!;
    cfg.data = { iv: "", ciphertext: "" };
    svc.set(cfg);

    const sls2 = secureLocalStorage({ storageKey });
    const view = await sls2.getData<Record<string, unknown>>();
    const keys = Object.keys(view);
    // Empty object view exposes only "clear"
    expect(keys).toEqual(["clear"]);
    view.clear();
  });
  /*
  it("resets to fresh store if device KEK is lost between sessions", async () => {
    const storageKey = "test:corrupt:lost-kek";
    const sls = secureLocalStorage({ storageKey });
    await sls.setData({ x: 1 });

    // Simulate losing the device KEK (e.g., new browser profile)
    await DeviceKeyProvider.deletePersistent();

    // New instance cannot unwrap; it resets to fresh config
    const sls2 = secureLocalStorage({ storageKey });
    const view = await sls2.getData<Record<string, unknown>>();
    expect(Object.keys(view)).toEqual(["clear"]);
    view.clear();
  });*/
});