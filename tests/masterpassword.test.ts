/* eslint-disable @typescript-eslint/no-floating-promises */
import "fake-indexeddb/auto";
import secureLocalStorage from "../src";
import { expect, test } from "bun:test";

// Argon2-browser loads WASM; in some CI environments this may not be available.
// If that happens, you can skip this test or ensure WASM is enabled.
const maybe = (globalThis as unknown as { WebAssembly?: unknown }).WebAssembly ? test : test.skip;

maybe("master password: set, unlock, export/import", async () => {
  const sls = secureLocalStorage({ storageKey: "test:sls-mp" });
  await sls.setData({ value1: 7 });

  await sls.setMasterPassword("correct horse battery staple");
  sls.lock();
  // Data is unreadable until unlock
  await expect(sls.getData()).rejects.toThrow();

  await sls.unlock("correct horse battery staple");
  const data = await sls.getData<{ value1: number }>();
  expect(data.value1).toBe(7);
  data.clear();

  // Export with custom export password and import into a fresh instance
  const exported = await sls.exportData("export-pass");
  const sls2 = secureLocalStorage({ storageKey: "test:sls-mp-2" });
  await sls2.importData(exported, "export-pass");
  const d2 = await sls2.getData<{ value1: number }>();
  expect(d2.value1).toBe(7);
  d2.clear();
});