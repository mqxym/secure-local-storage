import { LockedError } from "../errors";

export type SecureDataView<T extends Record<string, unknown>> = T & {
  clear(): void;
};

/**
 * A proxy-backed view of decrypted data that can securely wipe its memory.
 * After .clear(), property access throws LockedError.
 */
export function makeSecureDataView<T extends Record<string, unknown>>(
  payload: T
): SecureDataView<T> {
  let cleared = false;

  function clear() {
    // Overwrite values recursively
    const overwrite = (obj: unknown) => {
      if (!obj || typeof obj !== "object") return;
      for (const key of Object.keys(obj as Record<string, unknown>)) {
        const v = (obj as Record<string, unknown>)[key];
        if (v && typeof v === "object") overwrite(v);
        // @ts-expect-error safe overwrite
        (obj as Record<string, unknown>)[key] = null;
      }
    };
    overwrite(payload);
    cleared = true;
    // @ts-expect-error invalidate reference
    payload = {} as T;
  }

  const handler: ProxyHandler<Record<string, unknown>> = {
    get(_, prop: string) {
      if (prop === "clear") return clear;
      if (cleared) throw new LockedError("Decrypted data was cleared");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return (payload as any)[prop];
    },
    ownKeys() {
      if (cleared) throw new LockedError("Decrypted data was cleared");
      return [...Object.keys(payload), "clear"];
    },
    getOwnPropertyDescriptor() {
      return { enumerable: true, configurable: true };
    },
    has(_, prop) {
      if (prop === "clear") return true;
      if (cleared) throw new LockedError();
      return Object.prototype.hasOwnProperty.call(payload, prop);
    }
  };

  return new Proxy<Record<string, unknown>>({} as never, handler) as SecureDataView<T>;
}