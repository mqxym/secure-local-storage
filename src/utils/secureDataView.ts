import { LockedError, ValidationError } from "../errors";

export type SecureDataView<T extends Record<string, unknown>> = T & {
  clear(): void;
};

export function makeSecureDataView<T extends Record<string, unknown>>(payloadIn: T): SecureDataView<T> {
  let cleared = false;
  let payload: T = payloadIn;
  let nestedCache: WeakMap<object, object> = new WeakMap<object, object>(); // <-- make it reassignable

  function clear(): void {
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
    nestedCache = new WeakMap<object, object>();
  }

  const readonlyError = () => new ValidationError("SecureDataView is read-only; mutate via setData()");

  const wrapNested = (obj: unknown): unknown => {
    if (!obj || typeof obj !== "object") return obj;
    const cached = nestedCache.get(obj);
    if (cached) return cached;

    const proxied = new Proxy(obj as Record<string, unknown>, {
      get(target, prop: string | symbol) {
        if (cleared) throw new LockedError("Decrypted data was cleared");
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const v = (target as any)[prop];
        return typeof v === "object" && v !== null ? wrapNested(v) : v;
      },
      set() { throw readonlyError(); },
      defineProperty() { throw readonlyError(); },
      deleteProperty() { throw readonlyError(); },
      ownKeys(target) {
        if (cleared) throw new LockedError("Decrypted data was cleared");
        return Reflect.ownKeys(target);
      },
      getOwnPropertyDescriptor(target, prop) {
        if (cleared) throw new LockedError("Decrypted data was cleared");
        if (Object.prototype.hasOwnProperty.call(target, prop)) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const value = (target as any)[prop];
          return { configurable: true, enumerable: true, writable: false, value };
        }
        return undefined;
      },
      has(target, prop) {
        if (cleared) throw new LockedError("Decrypted data was cleared");
        return Reflect.has(target, prop);
      }
    });

    nestedCache.set(obj, proxied);
    return proxied;
  };

  const handler: ProxyHandler<Record<string, unknown>> = {
    get(_, prop: string | symbol) {
      if (prop === "clear") return clear;
      if (cleared) throw new LockedError("Decrypted data was cleared");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const v = (payload as any)[prop];
      return typeof v === "object" && v !== null ? wrapNested(v) : v;
    },
    set() { throw readonlyError(); },
    defineProperty() { throw readonlyError(); },
    deleteProperty() { throw readonlyError(); },
    ownKeys() {
      if (cleared) throw new LockedError("Decrypted data was cleared");
      return [...Object.keys(payload), "clear"];
    },
    getOwnPropertyDescriptor(_, prop: string | symbol) {
      if (prop === "clear") return { configurable: true, enumerable: true, writable: false, value: clear };
      if (cleared) throw new LockedError("Decrypted data was cleared");
      if (Object.prototype.hasOwnProperty.call(payload, prop)) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const value = (payload as any)[prop];
        return { configurable: true, enumerable: true, writable: false, value };
      }
      return undefined;
    },
    has(_, prop) {
      if (prop === "clear") return true;
      if (cleared) throw new LockedError("Decrypted data was cleared");
      return Object.prototype.hasOwnProperty.call(payload, prop);
    }
  };

  return new Proxy<Record<string, unknown>>({} as never, handler) as SecureDataView<T>;
}