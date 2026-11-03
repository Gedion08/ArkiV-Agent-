/** Typed error. `message` never contains plaintext, keys or other secrets. */
export class AfrError extends Error {
  readonly code: string;
  constructor(code: string, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "AfrError";
    this.code = code;
  }
}
