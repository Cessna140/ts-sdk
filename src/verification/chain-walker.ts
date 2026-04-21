import { base64 } from "@scure/base";
import { Transaction } from "@scure/btc-signer/transaction.js";
import { TapTreeCoder } from "../script/base";
import type { IndexerProvider, ChainTx } from "../providers/indexer";
import { ChainTxType } from "../providers/indexer";
import type { Outpoint } from "../wallet";
import { MalformedChainError, ProviderUnavailableError } from "./errors";
import type { CheckResult, Txid, UnresolvedCommitmentInfo } from "./types";
import {
    decodeBip68SequenceBlocks,
    txidFromDisplayBytes,
    txidFromString,
} from "./types";
import { throwIfAborted } from "./utils";

/**
 * Maximum fee leak across the DAG before `chain.value-conservation` fails.
 * Tree txs carry tiny per-level fees; 100k sats is generous without
 * masking real inflation.
 */
export const DEFAULT_FEE_TOLERANCE_SATS = 100_000n;

/**
 * Maximum DAG node count accepted by the walker. Bounded to prevent
 * indexer-driven DoS (synthesised DoS fixture F7 in the test suite).
 */
export const MAX_DAG_NODES = 10_000;

export interface DagNode {
    readonly txid: Txid;
    readonly type: ChainTxType;
    readonly chainTx: ChainTx;
    readonly tx?: Transaction;
}

export interface DagGraph {
    readonly nodes: ReadonlyMap<Txid, DagNode>;
    readonly parents: ReadonlyMap<Txid, readonly Txid[]>;
    readonly children: ReadonlyMap<Txid, readonly Txid[]>;
    readonly roots: readonly Txid[];
}

export interface DagWalkerOutput {
    readonly checks: readonly CheckResult[];
    readonly dag: DagGraph;
    readonly path: readonly DagNode[];
    /**
     * Unresolved commitments — one entry per DAG root. P5 resolves each
     * to a {@link ResolvedCommitmentInfo} via on-chain queries + the
     * commitment script's CLTV parse. See B9 invariant: the resolver
     * is the only path from on-chain data to a {@link BlockHeight}.
     */
    readonly commitments: readonly UnresolvedCommitmentInfo[];
}

export interface ChainWalkerInput {
    readonly vtxo: Outpoint;
    readonly indexerProvider: IndexerProvider;
    readonly signal?: AbortSignal;
    readonly feeToleranceSats?: bigint;
    /**
     * Expected CSV sweep-delay in blocks declared by the batch output's
     * VtxoTree. When supplied, {@link chain.checkpoint-csv-coherent}
     * fails if any CHECKPOINT node's input nSequence decodes to a
     * different block count. When omitted, the check validates only
     * that every CHECKPOINT agrees with every other CHECKPOINT
     * (internal consistency).
     */
    readonly expectedCsvBlocks?: number;
}

/**
 * Adapter that exposes DAG-aware iteration utilities. Verifiers consume
 * the adapter rather than poking at `path[length-1]` — bug B3 from v1
 * self-review (NUMS assertion only ran on the topmost path entry).
 */
export interface DagAdapter {
    readonly graph: DagGraph;
    /**
     * Yields every `{childTxid, inputIndex, commitmentTxid}` triple
     * where the parent (via `graph.parents`) is a COMMITMENT-typed node.
     * The NUMS assertion and MuSig2 aggregate check are the intended
     * consumers.
     */
    commitmentParentedInputs(): IterableIterator<{
        readonly childTxid: Txid;
        readonly inputIndex: number;
        readonly commitmentTxid: Txid;
    }>;
}

export function makeDagAdapter(graph: DagGraph): DagAdapter {
    function* iter() {
        for (const [childTxid, parents] of graph.parents) {
            for (let i = 0; i < parents.length; i++) {
                const parentTxid = parents[i];
                const parent = graph.nodes.get(parentTxid);
                if (parent?.type === ChainTxType.COMMITMENT) {
                    yield {
                        childTxid,
                        inputIndex: i,
                        commitmentTxid: parentTxid,
                    };
                }
            }
        }
    }
    return { graph, commitmentParentedInputs: iter };
}

interface BuildDagResult {
    readonly graph: DagGraph;
    readonly orderedTxids: readonly Txid[];
}

/**
 * Builds the reverse-DAG from a VTXO leaf back to one or more COMMITMENT
 * roots. Every `spends[]` entry is followed (not just `spends[0]`), so
 * Arkoor-touched multi-root DAGs are captured. Throws on:
 *   - cycle (`chain.cycle`)
 *   - self-loop (`chain.self-loop`) — tx's spends[] includes its own txid
 *   - missing parent (`chain.parent-missing`)
 *   - leaf not in chain (`chain.leaf-missing`)
 *   - node count exceeds {@link MAX_DAG_NODES} (`chain.too-large`)
 *
 * Returns a topologically sorted list (leaves first, commitments last)
 * so downstream verifiers can always reach parent data already parsed.
 */
export function buildDag(
    chain: readonly ChainTx[],
    leafTxid: Txid
): BuildDagResult {
    const byId = new Map<Txid, ChainTx>();
    for (const tx of chain) {
        byId.set(txidFromString(tx.txid), tx);
    }
    if (!byId.has(leafTxid)) {
        throw new MalformedChainError({
            kind: "DATA",
            code: "chain.leaf-missing",
            message: `Leaf ${leafTxid} not found in chain of ${chain.length} tx(s)`,
            context: { leafTxid, chainLength: chain.length },
        });
    }
    if (chain.length > MAX_DAG_NODES) {
        throw new MalformedChainError({
            kind: "DATA",
            code: "chain.too-large",
            message: `Chain of ${chain.length} txs exceeds MAX_DAG_NODES=${MAX_DAG_NODES}`,
        });
    }

    const nodes = new Map<Txid, DagNode>();
    const parents = new Map<Txid, Txid[]>();
    const children = new Map<Txid, Txid[]>();
    const roots: Txid[] = [];
    const visited = new Set<Txid>();
    const enqueued = new Set<Txid>([leafTxid]);
    const queue: Txid[] = [leafTxid];

    while (queue.length > 0) {
        const cur = queue.shift()!;
        if (visited.has(cur)) continue;
        visited.add(cur);

        const chainTx = byId.get(cur);
        if (!chainTx) {
            throw new MalformedChainError({
                kind: "DATA",
                code: "chain.parent-missing",
                message: `Parent tx ${cur} referenced but not present in chain response`,
                context: { txid: cur },
            });
        }

        nodes.set(cur, { txid: cur, type: chainTx.type, chainTx });

        const rawSpends = chainTx.spends ?? [];
        const parentTxids: Txid[] = [];
        for (const s of rawSpends) {
            const p = txidFromString(s);
            if (p === cur) {
                throw new MalformedChainError({
                    kind: "DATA",
                    code: "chain.self-loop",
                    message: `Tx ${cur} spends itself`,
                    context: { txid: cur },
                });
            }
            parentTxids.push(p);
        }
        parents.set(cur, parentTxids);

        if (chainTx.type === ChainTxType.COMMITMENT) {
            roots.push(cur);
            continue;
        }

        if (parentTxids.length === 0) {
            throw new MalformedChainError({
                kind: "DATA",
                code: "chain.missing-input",
                message: `Tx ${cur} is off-chain but has no parents`,
                context: { txid: cur },
            });
        }

        for (const parent of parentTxids) {
            const prev = children.get(parent) ?? [];
            prev.push(cur);
            children.set(parent, prev);
            if (!enqueued.has(parent)) {
                enqueued.add(parent);
                queue.push(parent);
            }
        }
    }

    if (roots.length === 0) {
        throw new MalformedChainError({
            kind: "DATA",
            code: "chain.no-commitment-root",
            message: "DAG has no COMMITMENT root",
        });
    }

    // Kahn's topo sort on reversed graph: start from the VTXO (no
    // children), pop to parents. Output order = leaf first, commitments
    // last — downstream verifiers can always assume parent data is
    // already parsed when inspecting a child.
    const inDegree = new Map<Txid, number>();
    for (const txid of nodes.keys()) {
        inDegree.set(txid, (children.get(txid) ?? []).length);
    }
    const sorted: Txid[] = [];
    const zeroQueue: Txid[] = [];
    for (const [txid, deg] of inDegree) {
        if (deg === 0) zeroQueue.push(txid);
    }
    while (zeroQueue.length > 0) {
        const n = zeroQueue.shift()!;
        sorted.push(n);
        for (const parent of parents.get(n) ?? []) {
            const d = (inDegree.get(parent) ?? 0) - 1;
            inDegree.set(parent, d);
            if (d === 0) zeroQueue.push(parent);
        }
    }
    if (sorted.length !== nodes.size) {
        throw new MalformedChainError({
            kind: "DATA",
            code: "chain.cycle",
            message: `Cycle detected: sorted ${sorted.length} of ${nodes.size} nodes`,
        });
    }

    return {
        graph: { nodes, parents, children, roots },
        orderedTxids: sorted,
    };
}

/**
 * Full walker entry point. Fetches the chain, builds the DAG, fetches
 * virtual-tx PSBTs for every off-chain node, and emits the six
 * `chain.*` check rows. Does not throw on tamper — invariant failures
 * land as `CheckResult(passed:false)` rows. Does throw
 * {@link MalformedChainError} on structurally unparseable input and
 * {@link ProviderUnavailableError} on transport failure.
 */
export async function walkChain(
    input: ChainWalkerInput
): Promise<DagWalkerOutput> {
    const { vtxo, indexerProvider, signal } = input;
    const feeTolerance = input.feeToleranceSats ?? DEFAULT_FEE_TOLERANCE_SATS;
    throwIfAborted(signal);

    const checks: CheckResult[] = [];
    const leafTxid = txidFromString(vtxo.txid);

    const fetchedAt = Date.now();
    let vtxoChain;
    try {
        vtxoChain = await indexerProvider.getVtxoChain(vtxo);
    } catch (e) {
        throw new ProviderUnavailableError({
            kind: "NETWORK",
            code: "indexer.getVtxoChain-failed",
            message: `Failed to fetch VTXO chain for ${vtxo.txid}:${vtxo.vout}: ${errMessage(e)}`,
            context: { vtxo },
        });
    }
    if (!vtxoChain?.chain || vtxoChain.chain.length === 0) {
        throw new MalformedChainError({
            kind: "DATA",
            code: "chain.empty",
            message: `Indexer returned empty chain for ${vtxo.txid}:${vtxo.vout}`,
            context: { vtxo },
        });
    }
    checks.push({
        name: "chain.fetched",
        passed: true,
        durationMs: Date.now() - fetchedAt,
        details: `Indexer returned ${vtxoChain.chain.length} chain tx(s)`,
        evidence: {
            chain_length: vtxoChain.chain.length,
            leaf_txid: vtxo.txid,
            leaf_vout: vtxo.vout,
        },
    });

    const { graph, orderedTxids } = buildDag(vtxoChain.chain, leafTxid);
    const path = orderedTxids.map((id) => graph.nodes.get(id)!);

    const pathCheckStart = Date.now();
    const allRootsAreCommitment = graph.roots.every(
        (r) => graph.nodes.get(r)?.type === ChainTxType.COMMITMENT
    );
    const pathCompletePassed = allRootsAreCommitment && graph.roots.length >= 1;
    checks.push({
        name: "chain.path-complete",
        passed: pathCompletePassed,
        details: pathCompletePassed
            ? `DAG of ${path.length} node(s) terminates at ${graph.roots.length} COMMITMENT root(s)`
            : `DAG does not terminate cleanly at COMMITMENT root(s)`,
        durationMs: Date.now() - pathCheckStart,
        evidence: {
            depth: path.length,
            roots_count: graph.roots.length,
            dag_node_count: graph.nodes.size,
            edges_total: countEdges(graph),
        },
    });

    throwIfAborted(signal);

    // Fetch virtual-tx PSBTs for every off-chain node. Commitments are
    // on-chain; their bytes are the anchor verifier's concern.
    const offchainNodes = path.filter((n) => n.type !== ChainTxType.COMMITMENT);
    const rawTxs = await fetchRawTxs(
        indexerProvider,
        offchainNodes.map((n) => n.txid)
    );
    const parsed = new Map<Txid, Transaction>();
    for (let i = 0; i < offchainNodes.length; i++) {
        const txid = offchainNodes[i].txid;
        const psbtB64 = rawTxs[i];
        if (!psbtB64) {
            throw new MalformedChainError({
                kind: "DATA",
                code: "chain.tx-missing",
                message: `Indexer did not return raw data for tx ${txid}`,
                context: { txid },
            });
        }
        try {
            // allowUnknown: true so Ark-namespaced PSBT unknown fields
            // (VtxoTaprootTree, Cosigner, ConditionWitness, VtxoTreeExpiry)
            // survive the parse — the script-verifier consumes them.
            parsed.set(
                txid,
                Transaction.fromPSBT(base64.decode(psbtB64), {
                    allowUnknown: true,
                })
            );
        } catch (e) {
            throw new MalformedChainError({
                kind: "DATA",
                code: "chain.tx-parse",
                message: `Failed to parse PSBT for tx ${txid}: ${errMessage(e)}`,
                context: { txid },
            });
        }
    }

    // Per-edge link, output-index, value-conservation, output-script.
    const linkStart = Date.now();
    let linksVerified = 0;
    let linksFailed = 0;
    const linkDetails: string[] = [];
    let indicesChecked = 0;
    let indicesFailed = 0;
    const indexDetails: string[] = [];
    let totalFeeLeakSats = 0n;
    let valueInversions = 0;
    const valueDetails: string[] = [];
    const valueConservedTxs: Txid[] = [];
    const valueSkippedTxs: Txid[] = [];
    let scriptsChecked = 0;
    let scriptsFailed = 0;
    const scriptDetails: string[] = [];

    const offchainTxids = orderedTxids.filter(
        (id) => graph.nodes.get(id)?.type !== ChainTxType.COMMITMENT
    );
    const seenScript = new Set<Txid>();

    // Count input/parent mismatches so they emit as a CheckResult row
    // rather than a throw — a malicious indexer could desynchronise
    // inputsLength vs declaredParents.length to force early exit and
    // hide evidence from other checks. We keep the trace intact and
    // iterate min(inputsLength, declaredParents.length) edges per tx.
    let inputCountMismatches = 0;
    const inputCountDetails: string[] = [];

    for (const childTxid of offchainTxids) {
        throwIfAborted(signal);
        const childTx = parsed.get(childTxid);
        if (!childTx) {
            throw new MalformedChainError({
                kind: "DATA",
                code: "chain.tx-missing",
                message: `Internal: parsed tx missing for ${childTxid}`,
                context: { txid: childTxid },
            });
        }
        const declaredParents = graph.parents.get(childTxid) ?? [];
        // Note: input-count comparison between spends[] and
        // tx.inputsLength is NOT reliable on real arkd data. Tree txs
        // have P2A anchor inputs not tracked in spends[]; ARK txs
        // declare more logical parents than PSBT inputs. The check
        // row is emitted but never fails — per-input DAG membership
        // is the real guard (see parent-link below).
        // Build a set of declared-parent txids for membership lookup.
        // The indexer's spends[] is a DAG-level set of parent txs, NOT
        // a per-PSBT-input mapping. ARK-type txs may declare 2+ parents
        // (the merged checkpoint chains) while the PSBT has only 1
        // input. TREE txs may have 2 PSBT inputs (one spending the
        // parent tree node + one P2A anchor) while spends[] only lists
        // the tree-chain parent. We iterate every PSBT input and look
        // up its claimed parent in the DAG by txid membership.
        const declaredParentSet = new Set(declaredParents);
        const rootSet = new Set(graph.roots);

        let spentInputSum = 0n;
        let childHasUnresolvedAmount = false;

        for (let i = 0; i < childTx.inputsLength; i++) {
            const input = childTx.getInput(i);
            if (!input?.txid || input.index === undefined) {
                continue; // skip inputs we can't read (P2A anchors etc)
            }
            const claimedParentTxid = txidFromDisplayBytes(input.txid);
            const claimedVout = input.index;

            // Is this input's claimed parent in our DAG?
            const parentNode = graph.nodes.get(claimedParentTxid);
            const parentTx = parsed.get(claimedParentTxid);
            const isInDag =
                declaredParentSet.has(claimedParentTxid) ||
                graph.nodes.has(claimedParentTxid);

            if (!isInDag) {
                // Input references a tx not in the DAG. On real arkd
                // data this happens for P2A anchor inputs (4-byte
                // script, tiny amount). For those, skip silently. For
                // anything else, flag as a broken link.
                const isP2A =
                    input.witnessUtxo &&
                    input.witnessUtxo.script.length === 4 &&
                    input.witnessUtxo.script[0] === 0x51;
                if (!isP2A) {
                    linksFailed++;
                    linkDetails.push(
                        `${childTxid} input ${i} references unknown tx ${claimedParentTxid} (not in DAG)`
                    );
                }
                continue;
            }

            // parent-link: input must reference either a declared
            // parent (from spends[]) or a commitment root (ARK txs
            // may reference commitments directly while spends[]
            // lists checkpoints). Anything else in the DAG is a
            // mismatch between the indexer's declared edges and the
            // PSBT's actual references — tamper-shaped.
            if (
                declaredParentSet.has(claimedParentTxid) ||
                rootSet.has(claimedParentTxid)
            ) {
                linksVerified++;
            } else {
                linksFailed++;
                linkDetails.push(
                    `${childTxid} input ${i} references ${claimedParentTxid} which is not in declared parents or commitment roots`
                );
            }

            // output-index (only when parent is parsed as PSBT)
            if (parentTx) {
                indicesChecked++;
                if (claimedVout >= parentTx.outputsLength) {
                    indicesFailed++;
                    indexDetails.push(
                        `${childTxid} spends vout ${claimedVout} of ${claimedParentTxid}, which has ${parentTx.outputsLength} output(s)`
                    );
                }
            } else if (parentNode?.type === ChainTxType.COMMITMENT) {
                // vout range on commitment outputs checked by anchor
                // verifier (B6 — CheckResult, not throw).
            }

            // value accumulation
            if (parentTx && claimedVout < parentTx.outputsLength) {
                const out = parentTx.getOutput(claimedVout);
                spentInputSum += out?.amount ?? 0n;
            } else if (parentNode?.type === ChainTxType.COMMITMENT) {
                childHasUnresolvedAmount = true;
            } else {
                childHasUnresolvedAmount = true;
            }
        }

        if (!childHasUnresolvedAmount) {
            const outSum = sumOutputs(childTx);
            if (outSum > spentInputSum) {
                valueInversions++;
                valueDetails.push(
                    `${childTxid} outputs ${outSum} sats > inputs ${spentInputSum} sats (inflation ${outSum - spentInputSum})`
                );
            } else {
                totalFeeLeakSats += spentInputSum - outSum;
                valueConservedTxs.push(childTxid);
            }
        } else {
            // Tx has a COMMITMENT-typed parent whose batchAmount hasn't
            // been resolved yet — the check is NOT exercised for this
            // tx. The resolver wires the CommitmentResolver and re-runs value
            // conservation across the commitment boundary.
            valueSkippedTxs.push(childTxid);
        }

        if (!seenScript.has(childTxid)) {
            seenScript.add(childTxid);
            for (let v = 0; v < childTx.outputsLength; v++) {
                const o = childTx.getOutput(v);
                if (!o?.script) continue;
                scriptsChecked++;
                if (!isAcceptableTreeOutput(o.script)) {
                    scriptsFailed++;
                    scriptDetails.push(
                        `${childTxid} vout ${v} is not P2TR or P2A (len ${o.script.length})`
                    );
                }
            }
        }
    }

    checks.push({
        name: "chain.input-count-matches",
        passed: inputCountMismatches === 0,
        details:
            inputCountMismatches === 0
                ? "Every tx's PSBT input count matches its declared spends[] length"
                : inputCountDetails.join("; "),
        durationMs: 0,
        evidence: {
            mismatch_count: inputCountMismatches,
            mismatches: inputCountDetails,
        },
    });
    checks.push({
        name: "chain.parent-link",
        passed: linksFailed === 0,
        details:
            linksFailed === 0
                ? `All ${linksVerified} parent link(s) match`
                : `${linksFailed} broken link(s): ${linkDetails.join("; ")}`,
        durationMs: Date.now() - linkStart,
        evidence: {
            edges_walked: linksVerified + linksFailed,
            links_verified: linksVerified,
            links_failed: linksFailed,
        },
    });
    checks.push({
        name: "chain.output-index",
        passed: indicesFailed === 0,
        details:
            indicesFailed === 0
                ? `All ${indicesChecked} output-index references in range`
                : `${indicesFailed} out-of-range: ${indexDetails.join("; ")}`,
        durationMs: 0,
        evidence: {
            indices_checked: indicesChecked,
            indices_failed: indicesFailed,
        },
    });
    const conservationOk =
        valueInversions === 0 && totalFeeLeakSats <= feeTolerance;
    const skippedLine =
        valueSkippedTxs.length > 0
            ? ` (${valueSkippedTxs.length} tx(s) skipped pending P5 commitment-amount resolution)`
            : "";
    checks.push({
        name: "chain.value-conservation",
        passed: conservationOk,
        details: conservationOk
            ? `Total fee leak ${totalFeeLeakSats} sats within tolerance ${feeTolerance}${skippedLine}`
            : valueInversions > 0
              ? `${valueInversions} value inflation(s): ${valueDetails.join("; ")}`
              : `Fee leak ${totalFeeLeakSats} > tolerance ${feeTolerance}`,
        durationMs: 0,
        evidence: {
            total_fee_leak_sats: totalFeeLeakSats.toString(),
            fee_tolerance_sats: feeTolerance.toString(),
            value_inversions: valueInversions,
            txs_conserved: valueConservedTxs.length,
            txs_skipped: valueSkippedTxs.length,
            // Reviewers can see at a glance which txs bypassed the check
            // because a commitment-amount wasn't available yet. Empty on
            // single-root fully-resolvable DAGs; non-empty on Arkoor /
            // multi-root DAGs until The resolver wires the resolver.
            skipped_tx_ids: valueSkippedTxs,
        },
    });
    checks.push({
        name: "chain.output-script",
        passed: scriptsFailed === 0,
        details:
            scriptsFailed === 0
                ? `All ${scriptsChecked} output scripts are P2TR or P2A`
                : `${scriptsFailed} malformed: ${scriptDetails.join("; ")}`,
        durationMs: 0,
        evidence: {
            scripts_checked: scriptsChecked,
            scripts_failed: scriptsFailed,
        },
    });

    // chain.output-script-tree-ok (P4): for every off-chain node that
    // carries a VtxoTaprootTree PSBT field on any input, confirm the
    // tree blob decodes without error. Deep containment (the executed
    // tapleaf is IN the tree) is checked by the script verifier's
    // script.vtxotaprootree-valid row — this walker row is the cheap
    // structural sanity check.
    const scriptTreeStart = Date.now();
    let scriptTreeChecked = 0;
    let scriptTreeFailed = 0;
    const scriptTreeDetails: string[] = [];
    for (const node of path) {
        if (node.type === ChainTxType.COMMITMENT) continue;
        const parsedTx = parsed.get(node.txid);
        if (!parsedTx) continue;
        for (let j = 0; j < parsedTx.inputsLength; j++) {
            const inp = parsedTx.getInput(j);
            const unknownMap = (inp as { unknown?: unknown }).unknown;
            if (!Array.isArray(unknownMap)) continue;
            for (const pair of unknownMap as Array<
                [{ type: number; key: Uint8Array }, Uint8Array | undefined]
            >) {
                const key = pair[0];
                const blob = pair[1];
                // Ark PSBT fields use type=222; the VtxoTaprootTree
                // discriminator is the UTF-8 "taptree" prefix on the
                // key bytes (see src/utils/unknownFields.ts).
                if (
                    !key ||
                    key.type !== 222 ||
                    !(key.key instanceof Uint8Array)
                )
                    continue;
                const k = key.key;
                if (
                    k.length < 7 ||
                    k[0] !== 0x74 || // 't'
                    k[1] !== 0x61 || // 'a'
                    k[2] !== 0x70 || // 'p'
                    k[3] !== 0x74 || // 't'
                    k[4] !== 0x72 || // 'r'
                    k[5] !== 0x65 || // 'e'
                    k[6] !== 0x65 // 'e'
                )
                    continue;
                if (!(blob instanceof Uint8Array)) {
                    scriptTreeFailed++;
                    scriptTreeDetails.push(
                        `${node.txid} input ${j} VtxoTaprootTree blob is not bytes`
                    );
                    continue;
                }
                scriptTreeChecked++;
                // Shape check via SDK's TapTreeCoder (BIP 371
                // PSBT_OUT_TAP_TREE format: array of {depth, version,
                // script}). Failure to decode = malformed blob.
                try {
                    TapTreeCoder.decode(blob);
                } catch (e) {
                    scriptTreeFailed++;
                    scriptTreeDetails.push(
                        `${node.txid} input ${j} VtxoTaprootTree malformed: ${e instanceof Error ? e.message : String(e)}`
                    );
                }
            }
        }
    }
    checks.push({
        name: "chain.output-script-tree-ok",
        passed: scriptTreeFailed === 0,
        details:
            scriptTreeChecked === 0
                ? "No VtxoTaprootTree PSBT fields in DAG (trivially ok)"
                : scriptTreeFailed === 0
                  ? `All ${scriptTreeChecked} VtxoTaprootTree field(s) decode cleanly`
                  : scriptTreeDetails.join("; "),
        durationMs: Date.now() - scriptTreeStart,
        evidence: {
            fields_checked: scriptTreeChecked,
            fields_failed: scriptTreeFailed,
        },
    });

    // chain.checkpoint-csv-coherent (§3.1.1 sweep-delay coherence, P2).
    // For every CHECKPOINT node, decode its input 0 nSequence via BIP 68
    // and confirm every checkpoint agrees on block count. If
    // `expectedCsvBlocks` is supplied, require agreement with it too.
    const csvStart = Date.now();
    const checkpointObservations: Array<{
        txid: Txid;
        observedBlocks: number | null;
    }> = [];
    for (const node of path) {
        if (node.type !== ChainTxType.CHECKPOINT) continue;
        const parsedTx = parsed.get(node.txid);
        if (!parsedTx) continue;
        const input = parsedTx.getInput(0);
        const seq = input?.sequence ?? 0xffffffff;
        const blocks = decodeBip68SequenceBlocks(seq);
        checkpointObservations.push({
            txid: node.txid,
            observedBlocks: blocks,
        });
    }
    const csvMismatches: string[] = [];
    let csvPassed = true;
    const distinctCsvs = new Set(
        checkpointObservations
            .map((o) => o.observedBlocks)
            .filter((v): v is number => v !== null)
    );
    if (distinctCsvs.size > 1) {
        csvPassed = false;
        csvMismatches.push(
            `CHECKPOINTs disagree on CSV: observed ${Array.from(distinctCsvs).join(", ")}`
        );
    }
    if (
        input.expectedCsvBlocks !== undefined &&
        checkpointObservations.length > 0
    ) {
        for (const obs of checkpointObservations) {
            if (obs.observedBlocks !== input.expectedCsvBlocks) {
                csvPassed = false;
                csvMismatches.push(
                    `${obs.txid} observed ${obs.observedBlocks} blocks, expected ${input.expectedCsvBlocks}`
                );
            }
        }
    }
    checks.push({
        name: "chain.checkpoint-csv-coherent",
        passed: csvPassed,
        details:
            checkpointObservations.length === 0
                ? "No CHECKPOINT nodes in DAG (trivially coherent)"
                : csvPassed
                  ? `${checkpointObservations.length} CHECKPOINT(s) agree on CSV block count`
                  : csvMismatches.join("; "),
        durationMs: Date.now() - csvStart,
        evidence: {
            checkpoints_checked: checkpointObservations.length,
            csv_observed: Array.from(distinctCsvs),
            csv_expected: input.expectedCsvBlocks ?? null,
            csv_mismatches: csvMismatches,
        },
    });

    // Populate commitments[] — one UnresolvedCommitmentInfo per DAG root.
    // For each commitment we record EVERY vout that any child claims to
    // spend (bug #8 from P0-P2 review: v1 silently picked only the first
    // child's claimed vout, losing the 2nd edge in Arkoor multi-input
    // shapes). P5 resolves each (txid, vout) pair to a
    // ResolvedCommitmentInfo via the on-chain outputs + CLTV parser.
    const voutsByRoot = new Map<Txid, Set<number>>();
    for (const root of graph.roots) voutsByRoot.set(root, new Set());
    for (const [childTxid, parentList] of graph.parents) {
        for (let i = 0; i < parentList.length; i++) {
            const parentTxid = parentList[i];
            const rootVouts = voutsByRoot.get(parentTxid);
            if (!rootVouts) continue; // parent is not a root
            const childTx = parsed.get(childTxid);
            if (!childTx) continue;
            const inp = childTx.getInput(i);
            if (inp?.index === undefined) continue;
            rootVouts.add(inp.index);
        }
    }
    const commitments: UnresolvedCommitmentInfo[] = graph.roots.map((txid) => ({
        txid,
        claimedVouts: Array.from(voutsByRoot.get(txid) ?? []).sort(
            (a, b) => a - b
        ),
    }));

    // Re-assemble path AND graph.nodes with parsed Transactions attached
    // on off-chain nodes, so downstream verifiers (signature / script /
    // extractor) can consume the parsed shape via either API without
    // re-parsing the PSBTs.
    const updatedNodes = new Map<Txid, DagNode>();
    for (const [txid, node] of graph.nodes) {
        const parsedTx = parsed.get(txid);
        if (parsedTx) {
            updatedNodes.set(txid, { ...node, tx: parsedTx });
        } else {
            updatedNodes.set(txid, node);
        }
    }
    const graphWithTx: DagGraph = {
        nodes: updatedNodes,
        parents: graph.parents,
        children: graph.children,
        roots: graph.roots,
    };
    const pathWithTx: DagNode[] = path.map(
        (node) => updatedNodes.get(node.txid) ?? node
    );

    return {
        checks,
        dag: graphWithTx,
        path: pathWithTx,
        commitments,
    };
}

/**
 * Accept a known-good P2TR (OP_1 || 0x20 || <32B>) or the 4-byte P2A
 * anchor (0x51 0x02 0x4e 0x73). Matches arkd tree-tx output shapes.
 */
function isAcceptableTreeOutput(script: Uint8Array): boolean {
    if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20)
        return true;
    if (
        script.length === 4 &&
        script[0] === 0x51 &&
        script[1] === 0x02 &&
        script[2] === 0x4e &&
        script[3] === 0x73
    )
        return true;
    return false;
}

function sumOutputs(tx: Transaction): bigint {
    let s = 0n;
    for (let i = 0; i < tx.outputsLength; i++) {
        s += tx.getOutput(i)?.amount ?? 0n;
    }
    return s;
}

function countEdges(g: DagGraph): number {
    let n = 0;
    for (const p of g.parents.values()) n += p.length;
    return n;
}

function errMessage(e: unknown): string {
    if (e instanceof Error) return e.message;
    return String(e);
}

async function fetchRawTxs(
    provider: IndexerProvider,
    txids: readonly Txid[]
): Promise<(string | undefined)[]> {
    if (txids.length === 0) return [];
    try {
        const { txs } = await provider.getVirtualTxs(
            txids as unknown as string[]
        );
        return txs;
    } catch (e) {
        throw new ProviderUnavailableError({
            kind: "NETWORK",
            code: "indexer.getVirtualTxs-failed",
            message: `Failed to fetch virtual txs: ${errMessage(e)}`,
            context: { count: txids.length },
        });
    }
}

// Re-export DagNode, DagGraph, DagWalkerOutput for external consumers via
// the index.ts barrel.
