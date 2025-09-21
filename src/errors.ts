export class SlsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SlsError";
  }
}

export class ValidationError extends SlsError {
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}

export class LockedError extends SlsError {
  constructor(message = "Session locked") {
    super(message);
    this.name = "LockedError";
  }
}

export class ModeError extends SlsError {
  constructor(message: string) {
    super(message);
    this.name = "ModeError";
  }
}

export class StorageFullError extends SlsError {
  constructor(message = "localStorage quota exceeded") {
    super(message);
    this.name = "StorageFullError";
  }
}

export class CryptoError extends SlsError {
  constructor(message: string) {
    super(message);
    this.name = "CryptoError";
  }
}

export class ImportError extends SlsError {
  constructor(message: string) {
    super(message);
    this.name = "ImportError";
  }
}

export class ExportError extends SlsError {
  constructor(message: string) {
    super(message);
    this.name = "ExportError";
  }
}

export class NotSupportedError extends SlsError {
  constructor(message: string) {
    super(message);
    this.name = "NotSupportedError";
  }
}