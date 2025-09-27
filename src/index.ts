import { SecureLocalStorage, type SecureLocalStorageOptions } from "./api/SecureLocalStorage";

export type { SecureLocalStorageOptions } from "./api/SecureLocalStorage";
export { SecureLocalStorage } from "./api/SecureLocalStorage";

/**
 * Creates and initializes a new `SecureLocalStorage` instance.
 *
 * This factory function is the recommended way to get started with the library.
 * It provides a convenient shorthand for `new SecureLocalStorage(opts)`.
 *
 * @param {SecureLocalStorageOptions} [opts] - Optional configuration to customize storage keys and other behavior.
 * @returns {SecureLocalStorage} A new instance of the `SecureLocalStorage` class.
 * @example
 * ```typescript
 * import secureLocalStorage from 'secure-local-storage';
 *
 * // Initialize with default options
 * const sls = secureLocalStorage();
 *
 * async function main() {
 *   await sls.setData({ secret: 'This is a secret' });
 *   const data = await sls.getData();
 *   console.log(data.value.secret); // "This is a secret"
 *   data.clear(); // clears read data memory
 * }
 *
 * main();
 * ```
 */
export default function secureLocalStorage(opts?: SecureLocalStorageOptions): SecureLocalStorage {
  return new SecureLocalStorage(opts);
}