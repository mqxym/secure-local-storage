import {
    PersistedConfig,
    PersistedConfigV2,
    PersistedConfigV3
  } from "../../types";
  import { SLS_CONSTANTS } from "../../constants";
  import { base64ToBytes } from "../../utils/base64";
  import { IdbConfig } from "../../crypto/DeviceKeyProvider";
  import { EncryptionManager } from "../../crypto/EncryptionManager";
  import { deriveKekFromPassword } from "../../crypto/KeyDerivation";

  export class VersionManager {
    constructor(
      public readonly storageKey: string,
      public readonly idbConfig: IdbConfig,
      private readonly enc: EncryptionManager
    ) {}

    public getAadFor(
      type: "wrap" | "data",
      config: PersistedConfig | null
    ): Uint8Array | undefined {
      if (config && this.isV3(config)) {
        const ctx = config.header.ctx ?? "store";
        if (type === "wrap") {
          return this.buildWrapAad(ctx, config.header.v);
        }
        return this.buildDataAad(
          ctx,
          config.header.v,
          config.header.iv,
          config.header.wrappedKey
        );
      }
      return undefined;
    }

    public isV3(config: PersistedConfig): config is PersistedConfigV3 {
      return (config.header as any).v === 3;
    }

    public isV2(config: PersistedConfig): config is PersistedConfigV2 {
      return (config.header as any).v === 2;
    }

    public isValidConfig(config: PersistedConfig | null): config is PersistedConfig {
      if (!config) return false;
      const h = config.header as any;
      const d = config.data as any;

      if (!SLS_CONSTANTS.SUPPORTED_VERSIONS.includes(h.v)) return false;
      if (typeof h.rounds !== "number" || h.rounds < 1) return false;
      if (typeof h.iv !== "string" || typeof h.wrappedKey !== "string")
        return false;
      if (!d || typeof d.iv !== "string" || typeof d.ciphertext !== "string")
        return false;

      if (h.rounds === 1) {
        if (h.salt !== "") return false;
      } else {
        if (typeof h.salt !== "string" || h.salt.length === 0) return false;
      }

      if (h.v === 3 && h.ctx && h.ctx !== "store") return false;

      try {
        base64ToBytes(h.iv);
        base64ToBytes(h.wrappedKey);
        if (d.iv) base64ToBytes(d.iv);
        if (d.ciphertext) base64ToBytes(d.ciphertext);
      } catch {
        return false;
      }
      return true;
    }

    public buildWrapAad(
      ctx: "store" | "export",
      version: number
    ): Uint8Array {
      const root = ctx === "store" ? this.storageKey : "export";
      const s = `sls|wrap|v${version}|${root}`;
      return new TextEncoder().encode(s);
    }

    public buildDataAad(
      ctx: "store" | "export",
      version: number,
      ivWrap: string,
      wrappedKey: string
    ): Uint8Array {
      const root = ctx === "store" ? this.storageKey : "export";
      const s = `sls|data|v${version}|${root}|${ivWrap}|${wrappedKey}`;
      return new TextEncoder().encode(s);
    }
  }