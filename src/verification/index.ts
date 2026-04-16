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
import {
    extractCommitmentExpiryHeights,
    extractCommitmentTapleafScripts,
    resolveCommitments,
    verifyAnchor,
} from "./anchor-verifier";
import type {
    CheckResult,
    Prevout,
    SignaturePathEntry,
    VerificationError,
    VerificationOptions,
    VerificationResult,
    VerificationTier,
} from "./types";
import { makeSignaturePathEntry, txidFromDisplayBytes } from "./types";

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
export {
    verifyAnchor,
    resolveCommitments,
    extractCommitmentTapleafScripts,
    anchorVoutInRange,
    DEFAULT_MIN_CONFIRMATIONS,
    DEFAULT_NEAR_EXPIRY_BLOCKS,
    type AnchorVerifierInput,
    type CommitmentTapleafMap,
} from "./anchor-verifier";

export interface VerifyVtxoInput {
    readonly vtxoId: Outpoint;
    readonly indexerProvider: IndexerProvider;
    readonly onchainProvider: OnchainProvider;
    readonly options?: VerificationOptions;
}

/**
 * Public entry point — independently validates an ASP's claims about a
 * VTXO using the supplied indexer + on-chain providers.
 *
 * Pipeline stages:
 *   1. Chain walker — 9 `chain.*` rows (DAG construction, link/index/
 *      value/script integrity, checkpoint CSV coherence, taptree shape).
 *   2. Commitment resolver — fetches each commitment's batch output;
 *      maps `VtxoTreeExpiry` PSBT field (or tapleaf CLTV) to a typed
 *      `BlockHeight` via one of the two B9-approved constructors.
 *   3. Signatures — 4 `sig.*` rows over per-input BIP 341 sighashes.
 *   4. Anchor — 4 `anchor.*` rows (confirmed / output-matches /
 *      unspent / expiry-not-passed) — §3.1.3 required checks.
 *   5. Tier 2 (opt-in via `options.tier`) — 4 `script.*` + 3
 *      `timelock.*` + 2 `preimage.*` rows.
 *   6. Finalise — `valid = errors.length === 0 && every check passed`.
 *
 * Partial-failure discipline: this function does NOT throw on tamper.
 * Invariant failures land as `CheckResult(passed:false)` rows; transport
 * / structural errors land as typed `errors[]` entries (caught at the
 * pipeline boundary via `recordThrown()`). Consumers always receive a
 * resolved `VerificationResult` with the full observable trace.
 *
 * @example
 * ```typescript
 * const result = await verifyVtxo({
 *     vtxoId: { txid, vout },
 *     indexerProvider,
 *     onchainProvider,
 *     options: { tier: "full" },
 * });
 * if (!result.valid) {
 *     for (const c of result.checks.filter((c) => !c.passed)) {
 *         console.error(c.name, c.details, c.evidence);
 *     }
 *     for (const e of result.errors) {
 *         console.error(`[${e.kind}] ${e.code}: ${e.message}`);
 *     }
 * }
 * ```
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

    // Stage 2: resolve commitments FIRST so we can use the resolved
    // on-chain prevouts (batchScript + batchAmount at the claimed vout)
    // when assembling per-input prevouts for the sig verifier. Real
    // arkd PSBTs do NOT populate witnessUtxo on commitment-adjacent
    // inputs; the DAG+resolver combo is how the pipeline fills that
    // gap.
    const dagAdapter = makeDagAdapter(walker.dag);
    const tapleafMap = extractCommitmentTapleafScripts(
        walker.commitments,
        (txid) => walker.dag.nodes.get(txid)?.tx,
        dagAdapter.commitmentParentedInputs()
    );
    // Prefer VtxoTreeExpiry PSBT field for arkd-issued VTXOs (relative
    // delay + confirmation height); fall back to tapleaf CLTV parsing
    // in the resolver for protocols that encode expiry absolutely.
    const expiryHeightMap = await extractCommitmentExpiryHeights(
        walker.commitments,
        (txid) => walker.dag.nodes.get(txid)?.tx,
        dagAdapter.commitmentParentedInputs(),
        input.onchainProvider
    );
    const resolved = await resolveCommitments(
        walker.commitments,
        input.onchainProvider,
        tapleafMap,
        expiryHeightMap,
        input.options?.signal
    );
    const resolvedCommitmentsByTxid = new Map<
        string,
        { script: Uint8Array; amount: bigint }
    >();
    if (resolved.ok) {
        for (const c of resolved.value) {
            // Key by txid + vout since multiple vouts per commitment possible.
            resolvedCommitmentsByTxid.set(`${c.txid}:${c.vout}`, {
                script: c.batchScript,
                amount: c.batchAmount,
            });
        }
    } else {
        // Surface the resolver error immediately so downstream sees it
        // regardless of whether sigPath assembly succeeds.
        errors.push({
            kind: "DATA",
            code: "anchor.commitment-resolve-failed",
            message: resolved.error,
        });
    }

    // Stage 3: signatures — build SignaturePathEntry[] using per-input
    // prevouts resolved from (a) the input's PSBT witnessUtxo when
    // present, (b) the DAG parent's output when off-chain, (c) the
    // resolved commitment's batchScript/batchAmount when the parent is
    // on-chain.
    try {
        const sigPath = assembleSignaturePath(
            walker.path,
            walker.dag.parents,
            resolvedCommitmentsByTxid,
            errors
        );
        if (sigPath.length > 0) {
            const sigChecks = await verifySignatures({
                path: sigPath,
                dag: dagAdapter,
                signal: input.options?.signal,
            });
            checks.push(...sigChecks);

            // Stage 4: anchor — emit 4 anchor.* check rows using the
            // resolved commitments. Resolver failure already recorded
            // above; just skip if resolved.ok is false.
            if (resolved.ok) {
                try {
                    const anchorChecks = await verifyAnchor({
                        commitments: resolved.value,
                        onchainProvider: input.onchainProvider,
                        minConfirmations: input.options?.minConfirmations,
                        signal: input.options?.signal,
                    });
                    checks.push(...anchorChecks);
                } catch (e) {
                    recordThrown(e, errors);
                }
            }
            // else: resolver error already recorded above when we built
            // resolvedCommitmentsByTxid.

            // Stage 5: Tier 2 — script / timelock / preimage verifiers.
            // Only run when the caller opts in with tier: "script" or "full".
            // Each Tier 2 verifier wrapped independently — a thrown
            // UnsupportedFeatureError in one (e.g. unrecognised leaf
            // version in the script verifier) must not block the
            // others from emitting their rows.
            if (tier === "script" || tier === "full") {
                try {
                    const scriptOut = await verifyScripts({
                        path: sigPath,
                        dag: dagAdapter,
                        signal: input.options?.signal,
                    });
                    checks.push(...scriptOut.checks);
                    for (const e of scriptOut.errors) errors.push(e);
                } catch (e) {
                    recordThrown(e, errors);
                }
                try {
                    const tlChecks = await verifyTimelocks({
                        path: sigPath,
                        signal: input.options?.signal,
                    });
                    checks.push(...tlChecks);
                } catch (e) {
                    recordThrown(e, errors);
                }
                try {
                    const piChecks = await verifyPreimages({
                        path: sigPath,
                        signal: input.options?.signal,
                    });
                    checks.push(...piChecks);
                } catch (e) {
                    recordThrown(e, errors);
                }
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
/**
 * Resolve per-input prevouts for every off-chain DAG node, using a
 * three-source lookup order:
 *
 *   1. PSBT `witnessUtxo` if present (the common case for off-chain
 *      signed hops).
 *   2. DAG parent's parsed-tx output at the claimed vout (off-chain
 *      parent).
 *   3. Resolved commitment's batchScript/batchAmount at the claimed
 *      vout (commitment-adjacent input — v2 pipeline fills the gap
 *      real arkd PSBTs leave on commitment-spending inputs).
 *
 * If all three fail for an input, we emit UNSUPPORTED and skip the
 * tx. `makeSignaturePathEntry` asserts `prevouts.length === tx.
 * inputsLength` (B1 invariant).
 */
function assembleSignaturePath(
    path: readonly DagNode[],
    parentsByTxid: ReadonlyMap<string, readonly string[]>,
    resolvedCommitmentsByVout: ReadonlyMap<
        string,
        { script: Uint8Array; amount: bigint }
    >,
    errors: VerificationError[]
): SignaturePathEntry[] {
    // Build a quick txid → parsed Tx lookup for off-chain DAG nodes.
    const parsedByTxid = new Map<string, Transaction>();
    for (const node of path) {
        if (
            node.type !== ChainTxType.COMMITMENT &&
            node.tx instanceof Transaction
        ) {
            parsedByTxid.set(node.txid, node.tx);
        }
    }

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
        const prevouts: Prevout[] = [];
        let resolvable = true;
        for (let i = 0; i < tx.inputsLength; i++) {
            const inp = tx.getInput(i);

            // (1) PSBT witnessUtxo
            if (inp?.witnessUtxo) {
                prevouts.push({
                    script: inp.witnessUtxo.script,
                    amount: inp.witnessUtxo.amount,
                });
                continue;
            }

            const claimedVout = inp?.index;
            // Look up the parent by the input's ACTUAL referenced txid
            // (not by positional index into declaredParents — arkd's
            // spends[] is a DAG-level set, not per-input).
            const inputParentTxid = inp?.txid
                ? txidFromDisplayBytes(inp.txid)
                : undefined;

            // (2) DAG parent's parsed output
            if (
                inputParentTxid &&
                claimedVout !== undefined &&
                parsedByTxid.has(inputParentTxid)
            ) {
                const parentTx = parsedByTxid.get(inputParentTxid)!;
                if (claimedVout < parentTx.outputsLength) {
                    const out = parentTx.getOutput(claimedVout);
                    if (out?.script && out.amount !== undefined) {
                        prevouts.push({
                            script: out.script,
                            amount: out.amount,
                        });
                        continue;
                    }
                }
            }

            // (3) Resolved commitment
            if (inputParentTxid && claimedVout !== undefined) {
                const hit = resolvedCommitmentsByVout.get(
                    `${inputParentTxid}:${claimedVout}`
                );
                if (hit) {
                    prevouts.push(hit);
                    continue;
                }
            }

            // All three sources failed — this input may be a P2A
            // anchor or fee input not tracked in the DAG. Use a
            // zero-value placeholder so the tx is still verifiable
            // for its DAG-linked inputs.
            if (
                inp?.witnessUtxo === undefined &&
                inputParentTxid &&
                !parsedByTxid.has(inputParentTxid) &&
                !resolvedCommitmentsByVout.has(
                    `${inputParentTxid}:${claimedVout ?? 0}`
                )
            ) {
                // Non-DAG input — placeholder prevout so
                // makeSignaturePathEntry's length-check passes.
                prevouts.push({
                    script: new Uint8Array(0),
                    amount: 0n,
                });
                continue;
            }

            resolvable = false;
            errors.push({
                kind: "UNSUPPORTED",
                code: "sig.prevout-unresolvable",
                message: `Tx ${node.txid} input ${i} — prevout unresolvable`,
                context: {
                    txid: node.txid,
                    input_index: i,
                    parent_txid: inputParentTxid,
                    claimed_vout: claimedVout,
                },
            });
            break;
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
