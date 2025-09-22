import { SecureLocalStorage, type SecureLocalStorageOptions } from "./api/SecureLocalStorage";
export type { SecureLocalStorageOptions } from "./api/SecureLocalStorage";
export { SecureLocalStorage } from "./api/SecureLocalStorage";
/**
 * Factory per your API:
 *
 * ```ts
 * const sls = secureLocalStorage(); // init
 * await sls.setData({ value1: 123 });
 * ```
 */
export default function secureLocalStorage(opts?: SecureLocalStorageOptions): SecureLocalStorage;
