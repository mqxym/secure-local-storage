# secure-local-storage

Secure arbitrary JSON data in `localStorage` using AES‑GCM‑256 envelope encryption.

* **Password‑less mode**: a non‑extractable KEK is generated and stored in **IndexedDB** (origin‑bound). Data is automatically available on this device.
* **Master‑password mode**: the KEK is derived from a user password via **Argon2id** (`argon2-browser`) with memory=64MiB, iterations=20, parallelism=1.

Built for browsers with the Web Crypto API. Bundled for ESM & CJS. Engine: **Bun ≥ 1.2.22** (for builds & tests).

> [!WARNING]
> This library secures data *at rest* in `localStorage`. It cannot protect against a compromised page runtime (XSS, devtools, malicious extensions). Always follow secure coding & CSP best practices.

---

## Live Demo

The demo includes most functionality provided by the API:
[https://mqxym.github.io/secure-local-storage/storage-example.html](https://mqxym.github.io/secure-local-storage/storage-example.html)

## Install

```bash
bun add @mqxym/secure-local-storage
# or
npm i @mqxym/secure-local-storage
```

## Quick start

```ts
import secureLocalStorage from "@mqxym/secure-local-storage";

const sls = secureLocalStorage( {storageKey: "my-sls-storage-name"}); // init (device mode by default)

await sls.setData({ value1: 123, nested: { a: "b" } });

const data = await sls.getData<{ value1: number; nested: { a: string } }>();
console.log(data.value1); // 123
data.clear();             // wipe decrypted copy from memory

// getData() returns a write-protected object.
// To modify it before passing into setData(), create a deep copy
// (e.g., using JSON serialization).
```

### Master password

```ts
await sls.setMasterPassword("correct horse battery staple"); // switch to master mode
sls.lock();                                  // remove keys from memory
await sls.unlock("correct horse battery staple"); // derive KEK and unlock
```

### Rotate, export, import

```ts
await sls.rotateMasterPassword("old pass", "new pass");
const exported = await sls.exportData("export-pass"); // JSON string
await sls.importData(exported, "export-pass");        // imports and rewraps to device mode by default
```

### API

```ts
const sls = secureLocalStorage( {storageKey: "my-sls-storage-name"});

console.log(sls.DATA_VERSION) // returns current data version (3)

// Customized usage
const sls = secureLocalStorage({
  storageKey: "tenant:123", // override localStorage key (recommended)
  idbConfig: {
    dbName: "SLS_KEYS_TENANT123", // override IndexedDB database name
    storeName: "keys",           // override object store name
    keyId: "deviceKek_v1"        // override key record id
  }
});

// Session / mode
await sls.unlock(masterPassword: string); // no-op when uninitialized / password-less mode
await sls.setMasterPassword(masterPassword: string);
await sls.removeMasterPassword();
await sls.rotateMasterPassword(oldMasterPassword: string, newMasterPassword: string); // switches to master password mode when in device key mode
sls.lock();
await sls.rotateKeys(); // password-less only
sls.isUsingMasterPassword() // true / false

// Data
const data = await sls.getData<T extends Record<string, unknown>>();
data.clear(); // securely wipes in-memory decrypted view
await sls.setData(setData: Record<string, unknown>);

// Import / export
const json = await sls.exportData(customExportPassword?: string); // JSON string
await sls.importData(json: string, exportOrMasterPassword?: string);

// Reset
await sls.clear(); // clears localStorage & IndexedDB and reinitializes in device mode
```

### How it works

* **Envelope encryption**:

  1. Generate a **DEK** (`CryptoKey`, AES‑GCM‑256). DEK encrypts your JSON data.
  2. **Wrap** (encrypt) the DEK with a **KEK**.

     * **Device mode**: KEK is a non‑extractable `CryptoKey` persisted in IndexedDB (origin‑scoped).
     * **Master mode**: KEK is derived via Argon2id (64MiB, 20 iters, p=1).
  3. Persist to `localStorage`:

     ```json
     {
       "header": { "v": 2, "salt": "", "rounds": 1, "iv": "...", "wrappedKey": "..." },
       "data":   { "iv": "...", "ciphertext": "..." }
     }
     ```

* **Non‑extractable keys**: KEK is non‑extractable. The DEK is generated extractable only to enable wrapping; when unwrapped for use it is kept non‑extractable. For rewrapping, it’s unwrapped into a short‑lived extractable key.

### Input validation & limits

* All public APIs validate input types and session/mode invariants.
* `localStorage` quotas vary by browser (commonly \~5-10 MB). The library throws a `StorageFullError` if writing exceeds quota.
* Data must be **JSON‑serializable**.

### Browser support

* Requires **Web Crypto** (`SubtleCrypto`) and **IndexedDB**. If IndexedDB refuses to store `CryptoKey` (rare older engines), a memory fallback is used (data remains secure, but device mode becomes ephemeral between reloads). For CI/testing, we polyfill IndexedDB via `fake-indexeddb`.

### Build & test

```bash
bun test
bun run build
```

* ESM output: `dist/esm/sls.browser.min.js`
* CJS output: `dist/cjs/sls.browser.min.cjs`
* Types: `dist/types/index.d.ts`

---

## Security considerations

* Clearing decrypted views calls a best‑effort memory wipe (overwriting object contents), but JS engines may keep copies; avoid holding long‑lived references to sensitive data.
* Use strong passwords in master mode. Argon2id settings: **20** iterations, **64 MiB** memory, **p=1**, **hashLen=32**.
* Consider Content Security Policy (CSP), dependency pinning, and extension risk mitigation.

---

## License

MIT
