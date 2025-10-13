// Portability.ts
import { SLS_CONSTANTS } from "../../constants";
import { ImportError } from "../../errors";
import type { PersistedConfig, PersistedConfigV3 } from "../../types";
import { EncryptionManager } from "../../crypto/EncryptionManager";
import { VersionManager } from "./VersionManager";

export type ExportSpec = {
  dek: CryptoKey;
  kek: CryptoKey;              // the KEK to wrap DEK for this bundle
  saltB64: string;             // salt to embed in bundle header
  rounds: number;              // argon2 rounds to embed
  mPw: boolean;                // header.mPw
};

export const Portability = {
  buildExportBundle: async (
    enc: EncryptionManager,
    versionManager: VersionManager,
    spec: ExportSpec,
    plainDataObj: unknown
  ): Promise<string> => {
    const ctx: PersistedConfigV3["header"]["ctx"] = "export";
    const wrapAad = versionManager.buildWrapAad(ctx, SLS_CONSTANTS.MIGRATION_TARGET_VERSION);
    const { ivWrap, wrappedKey } = await enc.wrapDek(spec.dek, spec.kek, wrapAad);

    const dataAad = versionManager.buildDataAad(
      ctx,
      SLS_CONSTANTS.MIGRATION_TARGET_VERSION,
      ivWrap,
      wrappedKey
    );
    const { iv, ciphertext } = await enc.encryptData(spec.dek, plainDataObj, dataAad);

    const bundle: PersistedConfigV3 = {
      header: {
        v: SLS_CONSTANTS.MIGRATION_TARGET_VERSION,
        salt: spec.saltB64,
        rounds: spec.rounds,
        iv: ivWrap,
        wrappedKey,
        mPw: spec.mPw,
        ctx
      },
      data: { iv, ciphertext }
    };
    return JSON.stringify(bundle);
  },

  parseAndClassify: (json: string, supported: readonly (2 | 3)[]) => {
    const MAX_BUNDLE_CHARS = 15 * 1024 * 1024; // 2 MiB
    if (json.length > MAX_BUNDLE_CHARS) {
    throw new ImportError("Export payload too large");
    }
    let t: unknown;
    try { t = JSON.parse(json); } catch { throw new ImportError("Invalid export structure"); }
    if (!t || typeof t !== "object" || !(t as any).header || !(t as any).data) {
      throw new ImportError("Invalid export structure");
    }
    const bundle = t as PersistedConfig;
    if (!supported.includes((bundle.header.v as 2 | 3))) {
      throw new ImportError(`Unsupported export version ${String((bundle as any).header?.v)}`);
    }
    const isMasterProtected =
      (bundle as any).header.mPw === true ||
      ((bundle.header as any).rounds > 1 && (bundle as any).header.mPw !== false);
    return { bundle, isMasterProtected };
  }
};