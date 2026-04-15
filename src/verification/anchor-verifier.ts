import type { CheckResult, CommitmentInfo } from "./types";

/**
 * Anchor verifier input. `commitments` is an array from day one — bug
 * B4 from v1 self-review where the verifier had a singular
 * `batchOutpoint` field and silently skipped value-conservation at the
 * commitment boundary. Every commitment carries its own `batchAmount`,
 * `batchScript`, and `batchExpiryHeight` (see {@link CommitmentInfo}),
 * so the verifier reads them unconditionally.
 */
export interface AnchorVerifierInput {
    readonly commitments: readonly CommitmentInfo[];
    readonly onchainProvider: unknown;
    readonly minConfirmations?: number;
    readonly signal?: AbortSignal;
}

export async function verifyAnchor(
    _input: AnchorVerifierInput
): Promise<readonly CheckResult[]> {
    throw new Error("verifyAnchor: not implemented until P5");
}

/**
 * Range-check a vout against a tx's outputsLength. Returns a
 * CheckResult; does NOT throw. Bug B6 from v1 self-review —
 * out-of-range vout was throwing MalformedChainError, inconsistent with
 * the partial-failure discipline every other verifier follows.
 *
 * This function is a canonical example of the "no throw in range-check"
 * discipline — lint rule enforces no `throw` statements inside this body.
 */
export function anchorVoutInRange(
    _vout: number,
    _outputsLength: number
): CheckResult {
    // P0 stub: real range check lands in P5. The signature (returns
    // CheckResult, not `asserts`, not `never`) is the invariant.
    return {
        name: "anchor.vout-in-range",
        passed: false,
        details: "not implemented until P5",
        durationMs: 0,
    };
}
