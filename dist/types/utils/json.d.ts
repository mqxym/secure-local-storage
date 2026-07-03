/**
 * Ensures a value is JSON-serializable and returns a deep-cloned plain JSON object.
 *
 * @remarks
 * The clone is produced via `JSON.parse(JSON.stringify(value))`, so the result
 * reflects standard JSON serialization semantics. Be aware of the following
 * findings when passing rich objects:
 *
 * - **`undefined` properties are dropped.** `{ a: undefined }` becomes `{}`.
 *   `undefined` array elements become `null`.
 * - **`Date` is silently coerced to an ISO string** (via `Date.prototype.toJSON`).
 *   The round-tripped value is a `string`, not a `Date`.
 * - **`Map`, `Set`, and other class instances lose their type.** `Map`/`Set`
 *   serialize to `{}`; only own enumerable, JSON-safe properties survive. A
 *   custom `toJSON()` method, if present, is honored.
 * - **Only the JSON-safe shape survives.** Prototypes, getters, and non-enumerable
 *   properties are not preserved.
 *
 * The following inputs are rejected with a {@link ValidationError}:
 * - Functions or symbols (anywhere in the structure).
 * - Circular references.
 * - Values that otherwise fail `JSON.stringify` (e.g. `BigInt`).
 *
 * @param value - The value to validate and deep-clone.
 * @returns A deep-cloned, plain JSON representation of `value`.
 * @throws {@link ValidationError} If the value is not JSON-serializable.
 */
export declare function toPlainJson<T>(value: T): T;
export declare function safeParseJson<T>(text: string): T;
