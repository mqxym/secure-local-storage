import {
    PersistedConfig,
    PersistedConfigV2,
    PersistedConfigV3
  } from "../../types";
  import { SLS_CONSTANTS } from "../../constants";
  import { base64ToBytes } from "../../utils/base64";
  import { IdbConfig } from "../../crypto/DeviceKeyProvider";
  import { EncryptionManager } from "../../crypto/EncryptionManager";

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

    public isValidConfig(config: unknown): config is PersistedConfig {
      if (!config || typeof config !== "object") return false;

      const c = config as { header?: unknown; data?: unknown };
      if (!c.header || typeof c.header !== "object") return false;
      if (!c.data || typeof c.data !== "object") return false;

      const h = c.header as {
        v?: unknown;
        salt?: unknown;
        rounds?: unknown;
        iv?: unknown;
        wrappedKey?: unknown;
        ctx?: unknown;
      };

      const d = c.data as { iv?: unknown; ciphertext?: unknown };

      const v = h.v as 2 | 3;
      if (!SLS_CONSTANTS.SUPPORTED_VERSIONS.includes(v)) return false;

      if (!Number.isInteger(h.rounds) || (h.rounds as number) < 1 || (h.rounds as number) > SLS_CONSTANTS.ARGON2.MAX_ITERATIONS) {
        return false;
      }

      if (typeof h.iv !== "string" || h.iv.length === 0) return false;
      if (typeof h.wrappedKey !== "string" || h.wrappedKey.length === 0) return false;
      if (typeof d.iv !== "string" || typeof d.ciphertext !== "string") return false;

      // persisted store config: ctx may be absent or "store"
      if (v === 3 && h.ctx !== undefined && h.ctx !== "store") return false;

      // both-or-none data fields (prevents silent data loss)
      const hasDataIv = d.iv.length > 0;
      const hasDataCt = d.ciphertext.length > 0;
      if (hasDataIv !== hasDataCt) return false;

      try {
        const ivWrap = base64ToBytes(h.iv);
        if (ivWrap.byteLength !== SLS_CONSTANTS.AES.IV_LENGTH) return false;

        const wk = base64ToBytes(h.wrappedKey);
        if (wk.byteLength === 0) return false;

        if (hasDataIv) {
          const dataIv = base64ToBytes(d.iv);
          if (dataIv.byteLength !== SLS_CONSTANTS.AES.IV_LENGTH) return false;

          const dataCt = base64ToBytes(d.ciphertext);
          if (dataCt.byteLength === 0) return false;
        }

        // salt semantics + salt base64 validation
        const rounds = h.rounds as number;
        if (rounds === 1) {
          if (h.salt !== "") return false;
        } else {
          if (typeof h.salt !== "string" || h.salt.length === 0) return false;
          const saltBytes = base64ToBytes(h.salt);
          if (saltBytes.byteLength !== SLS_CONSTANTS.SALT_LEN) return false;
        }
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