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
 */

import type { IndexerProvider } from "../providers/indexer";
import { ChainTxType } from "../providers/indexer";
import type { OnchainProvider } from "../providers/onchain";
import type { Outpoint } from "../wallet";
import { Transaction } from "@scure/btc-signer/transaction.js";
import { base64 } from "@scure/base";
import { makeDagAdapter, walkChain } from "./chain-walker";
import type { DagNode } from "./chain-walker";
import {
    MalformedChainError,
    ProviderUnavailableError,
    UnsupportedFeatureError,
    VerificationThrownError,
} from "./errors";
import { verifySignatures } from "./signature-verifier";
import { verifyScripts } from "./script-verifier";
import { verifyTimelocks } from "./timelock-verifier";
import { verifyPreimages } from "./preimage-verifier";
import type {
    CheckResult,
    Prevout,
    SignaturePathEntry,
    VerificationError,
    VerificationOptions,
    VerificationResult,
    VerificationTier,
} from "./types";
import { makeSignaturePathEntry } from "./types";

export * from "./types";
export * from "./errors";
export {
    buildDag,
    walkChain,
    makeDagAdapter,
    type DagGraph,
    type DagNode,
    type DagWalkerOutput,
    type DagAdapter,
    MAX_DAG_NODES,
    DEFAULT_FEE_TOLERANCE_SATS,
} from "./chain-walker";
export {
    verifySignatures,
    preimageWitnessV1Typed,
    type SignatureVerifierInput,
} from "./signature-verifier";
export {
    verifyScripts,
    type ScriptVerifierInput,
    type ScriptVerifierOutput,
} from "./script-verifier";
export {
    verifyTimelocks,
    type TimelockVerifierInput,
    DEFAULT_MIN_CSV_BLOCKS,
    DEFAULT_MAX_CSV_BLOCKS,
} from "./timelock-verifier";
export {
    verifyPreimages,
    decodeWitnessStack,
    MAX_PREIMAGE_CANDIDATES,
    type PreimageVerifierInput,
} from "./preimage-verifier";

export interface VerifyVtxoInput {
    readonly vtxoId: Outpoint;
    readonly indexerProvider: IndexerProvider;
    readonly onchainProvider: OnchainProvider;
    readonly options?: VerificationOptions;
}

/**
 * Public entry point. Orchestrates the full verification pipeline:
 *
 *   Stage 1 — chain walker (P1/P2): emits 8 chain.* checks.
 *   Stage 2 — signatures (P3): 4 sig.* checks using per-input prevouts.
 *   Stage 3 — Tier 2 script / timelock / preimage (P4).
 *   Stage 4 — anchor + commitment resolution (P5).
 *   Stage 5 — finalise: valid = all checks passed && zero errors.
 *
 * Only Stages 1–2 are implemented at P3. Tier 2 / anchor land at P4 / P5.
 *
 * Never throws for attack-catching reasons — failures land as
 * `CheckResult(passed:false)` or `errors[]` entries. Throws only via the
 * upstream MalformedChainError for genuinely unparseable input.
 */
export async function verifyVtxo(
    input: VerifyVtxoInput
): Promise<VerificationResult> {
    const started = Date.now();
    const tier: VerificationTier = input.options?.tier ?? "chain";
    const checks: CheckResult[] = [];
    const errors: VerificationError[] = [];

    // Stage 1: walk the DAG.
    let walker;
    try {
        walker = await walkChain({
            vtxo: input.vtxoId,
            indexerProvider: input.indexerProvider,
            signal: input.options?.signal,
        });
    } catch (e) {
        recordThrown(e, errors);
        return finalize(checks, errors, tier, started);
    }
    checks.push(...walker.checks);

    // Stage 2: signatures — build SignaturePathEntry[] from the walker's
    // parsed off-chain nodes. Commitment-adjacent inputs whose prevouts
    // aren't resolvable yet (P5 work) are marked UNSUPPORTED and the
    // tx is skipped for sig verification so the trace stays coherent.
    try {
        const sigPath = assembleSignaturePath(walker.path, errors);
        if (sigPath.length > 0) {
            const dagAdapter = makeDagAdapter(walker.dag);
            const sigChecks = await verifySignatures({
                path: sigPath,
                dag: dagAdapter,
                signal: input.options?.signal,
            });
            checks.push(...sigChecks);

            // Stage 3: Tier 2 — script / timelock / preimage verifiers.
            // Only run when the caller opts in with tier: "script" or "full".
            if (tier === "script" || tier === "full") {
                const scriptOut = await verifyScripts({
                    path: sigPath,
                    dag: dagAdapter,
                    signal: input.options?.signal,
                });
                checks.push(...scriptOut.checks);
                for (const e of scriptOut.errors) errors.push(e);
                const tlChecks = await verifyTimelocks({
                    path: sigPath,
                    signal: input.options?.signal,
                });
                checks.push(...tlChecks);
                const piChecks = await verifyPreimages({
                    path: sigPath,
                    signal: input.options?.signal,
                });
                checks.push(...piChecks);
            }
        } else {
            errors.push({
                kind: "UNSUPPORTED",
                code: "sig.no-resolvable-path",
                message:
                    "No tx in the DAG has all per-input prevouts resolvable from on-chain data yet (P5 wires commitment resolver)",
            });
        }
    } catch (e) {
        recordThrown(e, errors);
    }

    return finalize(checks, errors, tier, started);
}

/**
 * Resolve prevouts for every input of every off-chain DAG node. For
 * each input:
 *
 *   - parent is another off-chain DAG node ⇒ look up
 *     `parent.tx.getOutput(input.index)`.
 *   - parent is a COMMITMENT ⇒ prevout comes from on-chain data,
 *     resolved in P5. For P3, skip the tx (record UNSUPPORTED).
 *
 * `makeSignaturePathEntry` asserts `prevouts.length === tx.inputsLength`
 * at construction (B1 invariant).
 */
function assembleSignaturePath(
    path: readonly DagNode[],
    errors: VerificationError[]
): SignaturePathEntry[] {
    const entries: SignaturePathEntry[] = [];
    for (const node of path) {
        if (node.type === ChainTxType.COMMITMENT) continue;
        const tx = node.tx;
        if (!(tx instanceof Transaction)) {
            errors.push({
                kind: "UNSUPPORTED",
                code: "sig.parsed-tx-unavailable",
                message: `Walker did not surface a parsed Transaction for ${node.txid}`,
                context: { txid: node.txid },
            });
            continue;
        }
        // Attempt to resolve every input's prevout. Stop for this tx if
        // any input's prevout is unresolvable.
        const prevouts: Prevout[] = [];
        let resolvable = true;
        for (let i = 0; i < tx.inputsLength; i++) {
            const inp = tx.getInput(i);
            if (!inp?.witnessUtxo) {
                resolvable = false;
                errors.push({
                    kind: "UNSUPPORTED",
                    code: "sig.prevout-unresolvable",
                    message: `Tx ${node.txid} input ${i} has no witnessUtxo; commitment-adjacent prevouts land at P5`,
                    context: { txid: node.txid, input_index: i },
                });
                break;
            }
            prevouts.push({
                script: inp.witnessUtxo.script,
                amount: inp.witnessUtxo.amount,
            });
        }
        if (!resolvable) continue;
        try {
            entries.push(makeSignaturePathEntry(tx, prevouts));
        } catch (e) {
            errors.push({
                kind: "DATA",
                code: "sig.prevout-count-mismatch",
                message: e instanceof Error ? e.message : String(e),
                context: { txid: node.txid },
            });
        }
    }
    return entries;
}

function finalize(
    checks: readonly CheckResult[],
    errors: readonly VerificationError[],
    tier: VerificationTier,
    startedAt: number
): VerificationResult {
    const valid = errors.length === 0 && checks.every((c) => c.passed);
    return {
        valid,
        checks,
        errors,
        totalDurationMs: Date.now() - startedAt,
        tier,
    };
}

function recordThrown(e: unknown, errors: VerificationError[]): void {
    if (e instanceof VerificationThrownError) {
        errors.push(e.payload);
        return;
    }
    errors.push({
        kind: "DATA",
        code: "pipeline.unexpected-throw",
        message: e instanceof Error ? e.message : String(e),
    });
    // Silence unused-import warnings for error classes we don't narrow
    // on here (they're still exported from the barrel).
    void MalformedChainError;
    void ProviderUnavailableError;
    void UnsupportedFeatureError;
    void base64;
}
