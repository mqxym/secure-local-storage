import "./../setup";
import secureLocalStorage from "../../src";

describe("SecureLocalStorage - concurrency & readiness", () => {
  it("getData works immediately after construction (awaits the ready barrier)", async () => {
    const sls = secureLocalStorage({ storageKey: "test:conc:ready" });
    // No explicit wait between construction and use; the instance must self-serialize on `ready`.
    await sls.setData({ a: 1 });
    const view = await sls.getData<{ a: number }>();
    expect(view.a).toBe(1);
    view.clear();
  });

  it("concurrent setData calls all resolve and leave a consistent, readable state", async () => {
    const sls = secureLocalStorage({ storageKey: "test:conc:writes" });

    await Promise.all([
      sls.setData({ n: 1 }),
      sls.setData({ n: 2 }),
      sls.setData({ n: 3 }),
      sls.setData({ n: 4 }),
      sls.setData({ n: 5 })
    ]);

    // The final persisted state must be one of the written values and fully decryptable.
    const view = await sls.getData<{ n: number }>();
    expect([1, 2, 3, 4, 5]).toContain(view.n);
    view.clear();
  });

  it("serializes concurrent writes in submission order (last enqueued wins)", async () => {
    const sls = secureLocalStorage({ storageKey: "test:conc:order" });

    // Enqueue synchronously so ordering is deterministic via the internal op queue.
    const writes: Promise<void>[] = [];
    for (let i = 1; i <= 25; i++) writes.push(sls.setData({ n: i }));
    await Promise.all(writes);

    const view = await sls.getData<{ n: number }>();
    expect(view.n).toBe(25);
    view.clear();
  });

  it("a read enqueued after a write observes that write (no interleaving)", async () => {
    const sls = secureLocalStorage({ storageKey: "test:conc:rmw" });

    // Fire write then read without awaiting in between; the queue must order them.
    const writeP = sls.setData({ n: 7 });
    const readP = sls.getData<{ n: number }>();
    await writeP;
    const view = await readP;
    expect(view.n).toBe(7);
    view.clear();
  });

  it("concurrent getData calls each return an independent, readable view", async () => {
    const sls = secureLocalStorage({ storageKey: "test:conc:reads" });
    await sls.setData({ value: 42 });

    const [v1, v2, v3] = await Promise.all([
      sls.getData<{ value: number }>(),
      sls.getData<{ value: number }>(),
      sls.getData<{ value: number }>()
    ]);

    expect(v1.value).toBe(42);
    expect(v2.value).toBe(42);
    expect(v3.value).toBe(42);

    // Clearing one view must not affect the others (independent snapshots).
    v1.clear();
    expect(v2.value).toBe(42);
    v2.clear();
    v3.clear();
  });
});
