import "../setup";
import secureLocalStorage from "../../src";

describe("SecureLocalStorage.initialize() resets on invalid persisted config", () => {
  it("rounds < 1 triggers a fresh device-mode reinit", async () => {
    const storageKey = "test:init:reset:rounds";
    // v2 header but invalid rounds (0)
    const bad = JSON.stringify({
      header: { v: 2, salt: "", rounds: 0, iv: "YWJj", wrappedKey: "YWJj" },
      data: { iv: "", ciphertext: "" }
    });
    localStorage.setItem(storageKey, bad);

    const sls = secureLocalStorage({ storageKey });
    const view = await sls.getData<Record<string, unknown>>();
    expect(Object.keys(view)).toEqual(["clear"]); // empty object in fresh store
    view.clear();
  });
});