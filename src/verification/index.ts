/**
 * Client-side VTXO verification module.
 *
 * Implements assignment §3.1–§3.2 of the Arkade SDK take-home. A wallet
 * built on the SDK can use {@link verifyVtxo} to independently validate
 * every claim an ASP makes about a VTXO — from its leaf position in the
 * virtual transaction tree down to a confirmed on-chain commitment —
 * using only a user-controlled Bitcoin full node.
 *
 * ## Partial-failure semantics
 *
 * Unlike the SDK's internal validators (which throw on first failure),
 * this module accumulates `CheckResult(passed:false)` entries. The
 * observable trace is the whole point of the module — stopping after
 * one failure hides evidence for the tamper-demo and browser-demo
 * reviewers. The pipeline only throws when input is unparseable; see
 * {@link VerificationThrownError} subclasses.
 *
 * @example
 * const result = await verifyVtxo({
 *     vtxoId: "abc:0",
 *     indexerProvider,
 *     onchainProvider,
 *     options: { tier: "full", verbose: true },
 * });
 * if (!result.valid) {
 *     for (const check of result.checks.filter(c => !c.passed)) {
 *         console.error(check.name, check.details, check.evidence);
 *     }
 * }
 */

import type {
    VerificationOptions,
    VerificationResult,
    VerificationTier,
} from "./types";

export * from "./types";
export * from "./errors";

export interface VerifyVtxoInput {
    readonly vtxoId: string;
    readonly indexerProvider: unknown;
    readonly onchainProvider: unknown;
    readonly options?: VerificationOptions;
}

/**
 * Public entry point. In P0 this is a stub that returns an empty-check
 * result; real orchestration lands across phases P1 (chain walker) → P5
 * (pipeline assembly).
 */
export async function verifyVtxo(
    input: VerifyVtxoInput
): Promise<VerificationResult> {
    const tier: VerificationTier = input.options?.tier ?? "chain";
    return {
        valid: false,
        checks: [],
        errors: [
            {
                kind: "UNSUPPORTED",
                code: "pipeline.not-implemented",
                message:
                    "verifyVtxo is a P0 scaffold; implementation lands in P1–P5",
            },
        ],
        totalDurationMs: 0,
        tier,
    };
}
