import type { Transaction } from "@scure/btc-signer";
import type {
    CheckResult,
    PerInputPrevouts,
    Prevout,
    SighashType,
    SignaturePathEntry,
} from "./types";

/**
 * Wraps `@scure/btc-signer`'s `preimageWitnessV1`. The `sighashType`
 * parameter is REQUIRED (no default), forcing callers to thread the
 * parsed sighash byte from the 65-byte Schnorr sig — bug B5 from v1
 * self-review where the function hardcoded SIGHASH_DEFAULT.
 *
 * Stub — real implementation lands in P3.
 */
export function preimageWitnessV1Typed(
    _tx: Transaction,
    _inputIndex: number,
    _prevouts: PerInputPrevouts,
    _sighashType: SighashType
): Uint8Array {
    throw new Error("preimageWitnessV1Typed: not implemented until P3");
}

export interface SignatureVerifierInput {
    readonly path: readonly SignaturePathEntry[];
}

export async function verifySignatures(
    _input: SignatureVerifierInput
): Promise<readonly CheckResult[]> {
    throw new Error("verifySignatures: not implemented until P3");
}

// Re-export for convenience at module root
export type { SignaturePathEntry, Prevout, PerInputPrevouts };
