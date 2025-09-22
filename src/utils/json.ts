import { ValidationError } from "../errors";

/**
 * Ensures a value is JSON-serializable (no functions / symbols / circular refs).
 * Returns a deep-cloned plain JSON object.
 */
export function toPlainJson<T>(value: T): T {
  const seen = new WeakSet<object>();
  const replacer = (_key: string, v: unknown) => {
    const t = typeof v;
    if (t === "function" || t === "symbol") {
      throw new ValidationError("Data must be JSON-serializable (no functions/symbols)");
    }
    if (v && t === "object") {
      const o = v as object;
      if (seen.has(o)) {
        throw new ValidationError("Data must be JSON-serializable (no circular references)");
      }
      seen.add(o);
    }
    return v;
  };

  try {
    return JSON.parse(JSON.stringify(value, replacer)) as T;
  } catch (e) {
    if (e instanceof ValidationError) throw e;
    throw new ValidationError("Data must be JSON-serializable");
  }
}

export function safeParseJson<T>(text: string): T {
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new ValidationError("Invalid JSON input");
  }
}
