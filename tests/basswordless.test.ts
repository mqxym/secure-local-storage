/* eslint-disable @typescript-eslint/no-floating-promises */
import "fake-indexeddb/auto"; // allow IndexedDB in Bun tests
import secureLocalStorage from "../src";
import { expect, test } from "bun:test";

test("passwordless: set/get/clear", async () => {
  const sls = secureLocalStorage({ storageKey: "test:sls" });
  await sls.setData({ value1: 42, nested: { a: "b" } });

  const data = await sls.getData<{ value1: number; nested: { a: string } }>();
  expect(data.value1).toBe(42);
  expect(data.nested.a).toBe("b");

  // memory wipe
  data.clear();
  await expect(async () => {
    // @ts-expect-error access after clear should throw
    // eslint-disable-next-line @typescript-eslint/no-unused-expressions
    data.value1;
  }).toThrow();

  // ensure still decryptable after wipe of view
  const again = await sls.getData<{ value1: number }>();
  expect(again.value1).toBe(42);
  again.clear();
});

test("passwordless: lock prevents read", async () => {
  const sls = secureLocalStorage({ storageKey: "test:sls2" });
  await sls.setData({ v: 1 });
  sls.lock();
  await expect(sls.getData()).rejects.toThrow(); // LockedError
});