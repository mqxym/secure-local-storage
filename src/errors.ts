/**
 * Base class for all errors thrown by secure-local-storage.
 *
 * @remarks
 * Supports native error cause chaining (ES2022). When an underlying error is
 * caught and re-thrown as a domain error, the original is preserved on
 * {@link https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Error/cause | `Error.cause`}
 * for diagnostics, while the user-facing `message` stays stable (and, for
 * cryptographic failures, intentionally generic to avoid leaking detail).
 */
export class SlsError extends Error {
    constructor(message: string, options?: ErrorOptions) {
        super(message, options);
        this.name = "SlsError";
    }
}

export class ValidationError extends SlsError {
    constructor(message: string, options?: ErrorOptions) {
        super(message, options);
        this.name = "ValidationError";
    }
}

export class LockedError extends SlsError {
    constructor(message = "Session locked", options?: ErrorOptions) {
        super(message, options);
        this.name = "LockedError";
    }
}

export class ModeError extends SlsError {
    constructor(message: string, options?: ErrorOptions) {
        super(message, options);
        this.name = "ModeError";
    }
}

/**
 * Thrown when a write to `localStorage` fails because the storage quota was
 * exceeded.
 *
 * @remarks
 * The persisted bundle did **not** reach storage. The condition is typically
 * recoverable by freeing space (e.g. clearing other keys or reducing payload
 * size) and retrying. Contrast with {@link PersistenceError}, which signals a
 * write that returned but failed verification or a non-quota write failure.
 */
export class StorageFullError extends SlsError {
    constructor(message = "localStorage quota exceeded", options?: ErrorOptions) {
        super(message, options);
        this.name = "StorageFullError";
    }
}

export class CryptoError extends SlsError {
    constructor(message: string, options?: ErrorOptions) {
        super(message, options);
        this.name = "CryptoError";
    }
}

export class ImportError extends SlsError {
    constructor(message: string, options?: ErrorOptions) {
        super(message, options);
        this.name = "ImportError";
    }
}

export class ExportError extends SlsError {
    constructor(message: string, options?: ErrorOptions) {
        super(message, options);
        this.name = "ExportError";
    }
}

export class NotSupportedError extends SlsError {
    constructor(message: string, options?: ErrorOptions) {
        super(message, options);
        this.name = "NotSupportedError";
    }
}

/**
 * Thrown when persisting to `localStorage` fails for a reason other than an
 * exceeded quota.
 *
 * @remarks
 * Covers two cases:
 * - The `setItem` call returned but a read-back integrity check did not match
 *   what was written (silent truncation/corruption by the storage backend).
 * - A generic, non-quota write failure (e.g. storage disabled or a security
 *   exception).
 *
 * Unlike {@link StorageFullError}, retrying without changing conditions is
 * unlikely to help. The underlying error, when available, is attached via
 * `Error.cause`.
 */
export class PersistenceError extends SlsError {
    constructor(message: string, options?: ErrorOptions) {
        super(message, options);
        this.name = "PersistenceError";
    }
}
