import { ValidationError } from "../errors";

/**
 * Ensures a value is JSON-serializable (no functions / symbols / circular refs).
 * Returns a deep-cloned plain JSON object.
 */
export function toPlainJson<T>(value: T): T {
  try {
    return JSON.parse(JSON.stringify(value)) as T;
  } catch {
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