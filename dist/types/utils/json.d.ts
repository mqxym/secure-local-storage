/**
 * Ensures a value is JSON-serializable (no functions / symbols / circular refs).
 * Returns a deep-cloned plain JSON object.
 */
export declare function toPlainJson<T>(value: T): T;
export declare function safeParseJson<T>(text: string): T;
