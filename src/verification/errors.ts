import type { VerificationError, VerificationErrorKind } from "./types";

/**
 * Base class for every error thrown by the verification module. Consumers
 * get a single type to catch; the `payload` property carries the structured
 * shape for serialisation (tamper demo, browser demo).
 */
export class VerificationThrownError extends Error {
    readonly payload: VerificationError;

    constructor(payload: VerificationError) {
        super(payload.message);
        this.name = this.constructor.name;
        this.payload = payload;
    }
}

/**
 * Thrown when the chain response (indexer) or a parsed PSBT is structurally
 * malformed — e.g. missing parent, cycle, self-loop, unparseable tx hex.
 * Codes are stable (see docstring on {@link VerificationError}) so consumers
 * can dispatch on them.
 *
 * Codes produced by this module:
 *   - chain.empty
 *   - chain.cycle
 *   - chain.self-loop
 *   - chain.parent-missing
 *   - chain.tx-parse
 *   - chain.no-commitment-root
 *   - chain.commitment-vout-unresolved
 */
export class MalformedChainError extends VerificationThrownError {}

/**
 * Thrown when a provider call (indexer / onchain) fails at the transport
 * layer — HTTP non-2xx, fetch rejection, abort. Message always includes
 * the URL attempted, per SDK convention.
 */
export class ProviderUnavailableError extends VerificationThrownError {}

/**
 * Thrown when the verifier encounters a feature it does not yet implement
 * (e.g. a non-DEFAULT sighash, an unknown tapleaf version). Soft failure —
 * Tier 1 still completes; the specific input is skipped with an UNSUPPORTED
 * row in the trace.
 */
export class UnsupportedFeatureError extends VerificationThrownError {}

/**
 * Helper to build a VerificationError with consistent shape. Prefer this
 * over `new Error("...")` inside the module.
 */
export function makeVerificationError(
    kind: VerificationErrorKind,
    code: string,
    message: string,
    opts: { source?: string; context?: Record<string, unknown> } = {}
): VerificationError {
    return {
        kind,
        code,
        message,
        source: opts.source,
        context: opts.context,
    };
}
