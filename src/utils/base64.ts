export function bytesToBase64(bytes: ArrayBuffer | Uint8Array): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (u8.byteLength === 0) return "";
  let binary = "";
  for (let i = 0; i < u8.length; i++) binary += String.fromCharCode(u8[i] as number);
  if (typeof btoa === "function") return btoa(binary);
  // @ts-ignore
  return Buffer.from(binary, "binary").toString("base64");
}

import { ValidationError } from "../errors";

const MAX_BASE64_LEN = 15 * 1024 * 1024; 

export function base64ToBytes(b64: string): Uint8Array {
  if (typeof b64 !== "string" || b64.trim().length === 0) {
    throw new ValidationError("Base64 input must be a non-empty string");
  }

  const cleaned = b64.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (cleaned.length > MAX_BASE64_LEN) {
    throw new ValidationError("Base64 input too large");
  }

  // base64 length % 4 === 1 is never valid
  if (cleaned.length % 4 === 1) {
    throw new ValidationError("Invalid base64 input");
  }

  const normalized = cleaned + "=".repeat((4 - (cleaned.length % 4)) % 4);

  // validate charset + padding placement
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
    throw new ValidationError("Invalid base64 input");
  }

  try {
    if (typeof atob === "function") {
      const binary = atob(normalized);
      const out = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
      return out;
    }

    // Node/Bun fallback
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment,@typescript-eslint/no-explicit-any
    const buf: any = Buffer.from(normalized, "base64");
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  } catch (e) {
    throw new ValidationError("Invalid base64 input", { cause: e });
  }
}