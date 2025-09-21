import "./setup";
import secureLocalStorage from "../src";

describe("passwordless mode", () => {
  it("set/get/clear", async () => {
    const sls = secureLocalStorage({ storageKey: "test:sls" });
    await sls.setData({ value1: 42, nested: { a: "b" } });

    const data = await sls.getData<{ value1: number; nested: { a: string } }>();
    expect(data.value1).toBe(42);
    expect(data.nested.a).toBe("b");

    data.clear();
    // Synchronous throw (property access after clear)
    expect(() => (data as unknown as { value1: number }).value1).toThrow();

    // Ensure still decryptable after wiping the view
    const again = await sls.getData<{ value1: number }>();
    expect(again.value1).toBe(42);
    again.clear();
  });

  it("lock clears in-memory DEK but allows re-unwrapping in passwordless mode", async () => {
    const sls = secureLocalStorage({ storageKey: "test:sls2" });
    await sls.setData({ v: 1 });

    sls.lock(); // clears DEK from RAM

    // In passwordless mode, getData() re-unwraps using the device KEK and succeeds
    const data = await sls.getData<{ v: number }>();
    expect(data.v).toBe(1);
    data.clear();
  });
});