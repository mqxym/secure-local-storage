import { LockedError } from "../errors";

export type SecureDataView<T extends Record<string, unknown>> = T & {
  clear(): void;
};

export function makeSecureDataView<T extends Record<string, unknown>>(
  payloadIn: T
): SecureDataView<T> {
  let cleared = false;
  let payload: T = payloadIn;

  function clear() {
    const overwrite = (obj: unknown) => {
      if (!obj || typeof obj !== "object") return;
      const rec = obj as Record<string, unknown>;
      for (const key of Object.keys(rec)) {
        const v = rec[key];
        if (v && typeof v === "object") overwrite(v);
        rec[key] = null;
      }
    };
    overwrite(payload);
    cleared = true;
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