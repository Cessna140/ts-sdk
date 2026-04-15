import { base64, hex } from "@scure/base";
import { Transaction } from "@scure/btc-signer/transaction.js";
import type { IndexerProvider, ChainTx } from "../providers/indexer";
import { ChainTxType } from "../providers/indexer";
import type { Outpoint } from "../wallet";
import { MalformedChainError, ProviderUnavailableError } from "./errors";
import type { CheckResult, CommitmentInfo, Txid } from "./types";
import { decodeBip68SequenceBlocks, txidFromString } from "./types";

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
    readonly commitments: readonly CommitmentInfo[];
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
            parsed.set(txid, Transaction.fromPSBT(base64.decode(psbtB64)));
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
    let scriptsChecked = 0;
    let scriptsFailed = 0;
    const scriptDetails: string[] = [];

    const offchainTxids = orderedTxids.filter(
        (id) => graph.nodes.get(id)?.type !== ChainTxType.COMMITMENT
    );
    const seenScript = new Set<Txid>();

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
        if (childTx.inputsLength < declaredParents.length) {
            throw new MalformedChainError({
                kind: "DATA",
                code: "chain.input-count-mismatch",
                message: `Tx ${childTxid} declares ${declaredParents.length} parents but PSBT has ${childTx.inputsLength} input(s)`,
                context: {
                    txid: childTxid,
                    declared: declaredParents.length,
                    parsed: childTx.inputsLength,
                },
            });
        }

        let spentInputSum = 0n;
        let childHasUnresolvedAmount = false;

        for (let i = 0; i < declaredParents.length; i++) {
            const parentTxid = declaredParents[i];
            const parentNode = graph.nodes.get(parentTxid);
            const parentTx = parsed.get(parentTxid);
            const input = childTx.getInput(i);
            if (!input?.txid || input.index === undefined) {
                throw new MalformedChainError({
                    kind: "DATA",
                    code: "chain.missing-input",
                    message: `Tx ${childTxid} has no usable input ${i}`,
                    context: { txid: childTxid, input_index: i },
                });
            }
            const claimedParentTxid = txidFromBytesToDisplay(input.txid);
            const claimedVout = input.index;

            // parent-link (per edge)
            if (claimedParentTxid === parentTxid) {
                linksVerified++;
            } else {
                linksFailed++;
                linkDetails.push(
                    `${childTxid} input ${i} claims parent ${claimedParentTxid}, DAG says ${parentTxid}`
                );
            }

            // output-index (per edge, only when parent is parsed as PSBT)
            if (parentTx) {
                indicesChecked++;
                if (claimedVout >= parentTx.outputsLength) {
                    indicesFailed++;
                    indexDetails.push(
                        `${childTxid} spends vout ${claimedVout} of ${parentTxid}, which has ${parentTx.outputsLength} output(s)`
                    );
                }
            } else if (parentNode?.type === ChainTxType.COMMITMENT) {
                // For commitment edges, vout range against on-chain
                // outputs is checked in P5 by the anchor verifier via
                // anchorVoutInRange (CheckResult, not throw — B6).
            }

            // value accumulation
            if (parentTx && claimedVout < parentTx.outputsLength) {
                const out = parentTx.getOutput(claimedVout);
                spentInputSum += out?.amount ?? 0n;
            } else if (parentNode?.type === ChainTxType.COMMITMENT) {
                // Batch-output amount comes from CommitmentInfo
                // (resolved in P5); we cannot complete the sum here
                // without that, so mark unresolved.
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
            }
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
    checks.push({
        name: "chain.value-conservation",
        passed: valueInversions === 0 && totalFeeLeakSats <= feeTolerance,
        details:
            valueInversions === 0 && totalFeeLeakSats <= feeTolerance
                ? `Total fee leak ${totalFeeLeakSats} sats within tolerance ${feeTolerance}`
                : valueInversions > 0
                  ? `${valueInversions} value inflation(s): ${valueDetails.join("; ")}`
                  : `Fee leak ${totalFeeLeakSats} > tolerance ${feeTolerance}`,
        durationMs: 0,
        evidence: {
            total_fee_leak_sats: totalFeeLeakSats.toString(),
            fee_tolerance_sats: feeTolerance.toString(),
            value_inversions: valueInversions,
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

    // Populate commitments[] shape. batchScript/batchAmount/batchExpiryHeight
    // are resolved from on-chain data in P5 — here we only record the txid
    // and the vout each child claims. P5 fills in the rest via the
    // CommitmentResolver interface (returns Result<CommitmentInfo, error>,
    // B7 invariant).
    const commitmentBases = graph.roots.map((txid) => {
        let vout: number | undefined;
        for (const [childTxid, parentList] of graph.parents) {
            for (let i = 0; i < parentList.length; i++) {
                if (parentList[i] !== txid) continue;
                const childTx = parsed.get(childTxid);
                if (!childTx) continue;
                const inp = childTx.getInput(i);
                if (inp?.index !== undefined) {
                    vout = inp.index;
                    break;
                }
            }
            if (vout !== undefined) break;
        }
        return { txid, vout };
    });
    // Commitments are only fully materialised in P5 (batchScript/amount/
    // expiryHeight come from on-chain + CLTV parser). Pre-P5 we expose the
    // shape with vout resolved; callers will route through P5 for the rest.
    const commitments = commitmentBases
        .filter((c): c is { txid: Txid; vout: number } => c.vout !== undefined)
        .map(
            (c) =>
                ({
                    txid: c.txid,
                    vout: c.vout,
                    // P5 fills these in; the walker cannot. Placeholders
                    // are explicit so consumers see where the gap is.
                    batchScript: new Uint8Array(0),
                    batchAmount: 0n,
                    batchExpiryHeight:
                        0 as unknown as CommitmentInfo["batchExpiryHeight"],
                }) as CommitmentInfo
        );

    return { checks, dag: graph, path, commitments };
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

function txidFromBytesToDisplay(bytes: Uint8Array): Txid {
    // @scure/btc-signer stores PSBT input.txid bytes already in display
    // byte-order (the same order that `Transaction.id` returns). A raw
    // hex.encode is the correct conversion; a reverse here would double-
    // reverse and break the B2 parent-link invariant.
    if (bytes.length !== 32) {
        throw new Error(
            `txidFromBytesToDisplay: expected 32 bytes, got ${bytes.length}`
        );
    }
    return hex.encode(bytes) as Txid;
}

function errMessage(e: unknown): string {
    if (e instanceof Error) return e.message;
    return String(e);
}

function throwIfAborted(signal?: AbortSignal): void {
    if (signal?.aborted) {
        throw new MalformedChainError({
            kind: "UNSUPPORTED",
            code: "chain.aborted",
            message: "Chain walk was aborted via AbortSignal",
        });
    }
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
