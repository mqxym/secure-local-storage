export declare class SlsError extends Error {
    constructor(message: string);
}
export declare class ValidationError extends SlsError {
    constructor(message: string);
}
export declare class LockedError extends SlsError {
    constructor(message?: string);
}
export declare class ModeError extends SlsError {
    constructor(message: string);
}
export declare class StorageFullError extends SlsError {
    constructor(message?: string);
}
export declare class CryptoError extends SlsError {
    constructor(message: string);
}
export declare class ImportError extends SlsError {
    constructor(message: string);
}
export declare class ExportError extends SlsError {
    constructor(message: string);
}
export declare class NotSupportedError extends SlsError {
    constructor(message: string);
}
