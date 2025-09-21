// ArrayBuffer/Uint8Array <-> base64 (URL-safe not required here)
export function bytesToBase64(bytes: ArrayBuffer | Uint8Array): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (let i = 0; i < u8.length; i++) binary += String.fromCharCode(u8[i]);
  // btoa is available in browsers & Bun; fallback to Buffer if present
  if (typeof btoa === "function") return btoa(binary);
  // @ts-ignore Buffer may exist in some runtimes
  return Buffer.from(binary, "binary").toString("base64");
}

export function base64ToBytes(b64: string): Uint8Array {
  if (typeof atob === "function") {
    const binary = atob(b64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }
  // @ts-ignore Buffer may exist in some runtimes
  const buf = Buffer.from(b64, "base64");
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}