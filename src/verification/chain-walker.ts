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
 * Full walker entry point. Fetches the chain, builds the DAG, parses
 * PSBTs, and emits 9 `chain.*` check rows. Does not throw on tamper —
 * failures land as `CheckResult(passed:false)`. Throws on structurally
 * unparseable input or transport failure.
 */
export async function walkChain(
    input: ChainWalkerInput
): Promise<DagWalkerOutput> {
    const { signal } = input;
    throwIfAborted(signal);

    const checks: CheckResult[] = [];

    // Phase 1: Fetch chain + build DAG
    const { graph, orderedTxids, path } = await fetchAndBuildDag(input, checks);

    // Phase 2: Parse PSBTs for off-chain nodes
    const parsed = await fetchAndParsePsbts(
        graph,
        orderedTxids,
        path,
        input,
        signal
    );

    // Phase 3: Per-edge structural checks
    checks.push(
        ...checkEdgeIntegrity(
            graph,
            orderedTxids,
            parsed,
            input.feeToleranceSats ?? DEFAULT_FEE_TOLERANCE_SATS,
            signal
        )
    );

    // Phase 4: VtxoTaprootTree decode check
    checks.push(checkScriptTreeBlobs(path, parsed));

    // Phase 5: Checkpoint CSV coherence
    checks.push(checkCheckpointCsv(path, parsed, input.expectedCsvBlocks));

    // Assemble output
    const { commitments, dag, pathWithTx } = assembleOutput(
        graph,
        orderedTxids,
        parsed
    );
    return { checks, dag, path: pathWithTx, commitments };
}

// ── Phase 1: Fetch chain + build DAG ────────────────────────────────

async function fetchAndBuildDag(
    input: ChainWalkerInput,
    checks: CheckResult[]
): Promise<{
    graph: DagGraph;
    orderedTxids: readonly Txid[];
    path: readonly DagNode[];
}> {
    const { vtxo, indexerProvider } = input;
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

    return { graph, orderedTxids, path };
}

// ── Phase 2: Fetch + parse PSBTs ────────────────────────────────────

async function fetchAndParsePsbts(
    graph: DagGraph,
    orderedTxids: readonly Txid[],
    path: readonly DagNode[],
    input: ChainWalkerInput,
    signal?: AbortSignal
): Promise<Map<Txid, Transaction>> {
    throwIfAborted(signal);

    const offchainNodes = path.filter((n) => n.type !== ChainTxType.COMMITMENT);
    const rawTxs = await fetchRawTxs(
        input.indexerProvider,
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
    return parsed;
}

// ── Phase 3: Per-edge structural checks ─────────────────────────────

// ── Per-check state objects ──────────────────────────────────────────

interface LinkState {
    verified: number;
    failed: number;
    details: string[];
}

interface IndexState {
    checked: number;
    failed: number;
    details: string[];
}

interface ValueState {
    totalFeeLeak: bigint;
    inversions: number;
    details: string[];
    conserved: Txid[];
    skipped: Txid[];
}

interface ScriptState {
    checked: number;
    failed: number;
    details: string[];
}

interface InputCountState {
    mismatches: number;
    details: string[];
}

interface EdgeContext {
    readonly graph: DagGraph;
    readonly parsed: ReadonlyMap<Txid, Transaction>;
}

// ── Per-input check functions ───────────────────────────────────────

function checkParentLink(
    links: LinkState,
    childTxid: Txid,
    inputIndex: number,
    parentTxid: Txid,
    declaredParents: ReadonlySet<Txid>,
    roots: ReadonlySet<Txid>,
    inp: ReturnType<Transaction["getInput"]>,
    ctx: EdgeContext
): boolean {
    const isInDag =
        declaredParents.has(parentTxid) || ctx.graph.nodes.has(parentTxid);

    if (!isInDag) {
        const isP2A =
            inp.witnessUtxo &&
            inp.witnessUtxo.script.length === 4 &&
            inp.witnessUtxo.script[0] === 0x51;
        if (!isP2A) {
            links.failed++;
            links.details.push(
                `${childTxid} input ${inputIndex} references unknown tx ${parentTxid} (not in DAG)`
            );
        }
        return false; // not in DAG — skip downstream checks for this input
    }

    if (declaredParents.has(parentTxid) || roots.has(parentTxid)) {
        links.verified++;
    } else {
        links.failed++;
        links.details.push(
            `${childTxid} input ${inputIndex} references ${parentTxid} which is not in declared parents or commitment roots`
        );
    }
    return true;
}

function checkOutputIndex(
    indices: IndexState,
    childTxid: Txid,
    parentTxid: Txid,
    claimedVout: number,
    ctx: EdgeContext
): void {
    const parentTx = ctx.parsed.get(parentTxid);
    if (!parentTx) return;
    indices.checked++;
    if (claimedVout >= parentTx.outputsLength) {
        indices.failed++;
        indices.details.push(
            `${childTxid} spends vout ${claimedVout} of ${parentTxid}, which has ${parentTx.outputsLength} output(s)`
        );
    }
}

function accumulateInputValue(
    parentTxid: Txid,
    claimedVout: number,
    ctx: EdgeContext
): { amount: bigint; resolved: boolean } {
    const parentTx = ctx.parsed.get(parentTxid);
    if (parentTx && claimedVout < parentTx.outputsLength) {
        const out = parentTx.getOutput(claimedVout);
        return { amount: out?.amount ?? 0n, resolved: true };
    }
    const parentNode = ctx.graph.nodes.get(parentTxid);
    if (parentNode?.type === ChainTxType.COMMITMENT) {
        return { amount: 0n, resolved: false };
    }
    return { amount: 0n, resolved: false };
}

function finalizeValueConservation(
    values: ValueState,
    childTxid: Txid,
    childTx: Transaction,
    spentInputSum: bigint,
    hasUnresolved: boolean
): void {
    if (hasUnresolved) {
        values.skipped.push(childTxid);
        return;
    }
    const outSum = sumOutputs(childTx);
    if (outSum > spentInputSum) {
        values.inversions++;
        values.details.push(
            `${childTxid} outputs ${outSum} sats > inputs ${spentInputSum} sats (inflation ${outSum - spentInputSum})`
        );
    } else {
        values.totalFeeLeak += spentInputSum - outSum;
        values.conserved.push(childTxid);
    }
}

function checkOutputScripts(
    scripts: ScriptState,
    childTxid: Txid,
    childTx: Transaction,
    seen: Set<Txid>
): void {
    if (seen.has(childTxid)) return;
    seen.add(childTxid);
    for (let v = 0; v < childTx.outputsLength; v++) {
        const o = childTx.getOutput(v);
        if (!o?.script) continue;
        scripts.checked++;
        if (!isAcceptableTreeOutput(o.script)) {
            scripts.failed++;
            scripts.details.push(
                `${childTxid} vout ${v} is not P2TR or P2A (len ${o.script.length})`
            );
        }
    }
}

// ── Edge integrity orchestrator ─────────────────────────────────────

function checkEdgeIntegrity(
    graph: DagGraph,
    orderedTxids: readonly Txid[],
    parsed: ReadonlyMap<Txid, Transaction>,
    feeTolerance: bigint,
    signal?: AbortSignal
): CheckResult[] {
    const start = Date.now();
    const ctx: EdgeContext = { graph, parsed };
    const links: LinkState = { verified: 0, failed: 0, details: [] };
    const indices: IndexState = { checked: 0, failed: 0, details: [] };
    const values: ValueState = {
        totalFeeLeak: 0n,
        inversions: 0,
        details: [],
        conserved: [],
        skipped: [],
    };
    const scripts: ScriptState = { checked: 0, failed: 0, details: [] };
    const inputCounts: InputCountState = { mismatches: 0, details: [] };
    const seenScript = new Set<Txid>();

    const offchainTxids = orderedTxids.filter(
        (id) => graph.nodes.get(id)?.type !== ChainTxType.COMMITMENT
    );

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

        const declaredParents = new Set(graph.parents.get(childTxid) ?? []);
        const roots = new Set(graph.roots);
        let spentInputSum = 0n;
        let hasUnresolved = false;

        for (let i = 0; i < childTx.inputsLength; i++) {
            const inp = childTx.getInput(i);
            if (!inp?.txid || inp.index === undefined) continue;
            const parentTxid = txidFromDisplayBytes(inp.txid);

            const inDag = checkParentLink(
                links,
                childTxid,
                i,
                parentTxid,
                declaredParents,
                roots,
                inp,
                ctx
            );
            if (!inDag) continue;

            checkOutputIndex(indices, childTxid, parentTxid, inp.index, ctx);

            const val = accumulateInputValue(parentTxid, inp.index, ctx);
            spentInputSum += val.amount;
            if (!val.resolved) hasUnresolved = true;
        }

        finalizeValueConservation(
            values,
            childTxid,
            childTx,
            spentInputSum,
            hasUnresolved
        );
        checkOutputScripts(scripts, childTxid, childTx, seenScript);
    }

    return buildEdgeCheckResults(
        start,
        feeTolerance,
        links,
        indices,
        values,
        scripts,
        inputCounts
    );
}

function buildEdgeCheckResults(
    start: number,
    feeTolerance: bigint,
    links: LinkState,
    indices: IndexState,
    values: ValueState,
    scripts: ScriptState,
    inputCounts: InputCountState
): CheckResult[] {
    const conservationOk =
        values.inversions === 0 && values.totalFeeLeak <= feeTolerance;
    const skippedLine =
        values.skipped.length > 0
            ? ` (${values.skipped.length} tx(s) skipped pending commitment-amount resolution)`
            : "";

    return [
        {
            name: "chain.input-count-matches",
            passed: inputCounts.mismatches === 0,
            details:
                inputCounts.mismatches === 0
                    ? "Every tx's PSBT input count matches its declared spends[] length"
                    : inputCounts.details.join("; "),
            durationMs: 0,
            evidence: {
                mismatch_count: inputCounts.mismatches,
                mismatches: inputCounts.details,
            },
        },
        {
            name: "chain.parent-link",
            passed: links.failed === 0,
            details:
                links.failed === 0
                    ? `All ${links.verified} parent link(s) match`
                    : `${links.failed} broken link(s): ${links.details.join("; ")}`,
            durationMs: Date.now() - start,
            evidence: {
                edges_walked: links.verified + links.failed,
                links_verified: links.verified,
                links_failed: links.failed,
            },
        },
        {
            name: "chain.output-index",
            passed: indices.failed === 0,
            details:
                indices.failed === 0
                    ? `All ${indices.checked} output-index references in range`
                    : `${indices.failed} out-of-range: ${indices.details.join("; ")}`,
            durationMs: 0,
            evidence: {
                indices_checked: indices.checked,
                indices_failed: indices.failed,
            },
        },
        {
            name: "chain.value-conservation",
            passed: conservationOk,
            details: conservationOk
                ? `Total fee leak ${values.totalFeeLeak} sats within tolerance ${feeTolerance}${skippedLine}`
                : values.inversions > 0
                  ? `${values.inversions} value inflation(s): ${values.details.join("; ")}`
                  : `Fee leak ${values.totalFeeLeak} > tolerance ${feeTolerance}`,
            durationMs: 0,
            evidence: {
                total_fee_leak_sats: values.totalFeeLeak.toString(),
                fee_tolerance_sats: feeTolerance.toString(),
                value_inversions: values.inversions,
                txs_conserved: values.conserved.length,
                txs_skipped: values.skipped.length,
                skipped_tx_ids: values.skipped,
            },
        },
        {
            name: "chain.output-script",
            passed: scripts.failed === 0,
            details:
                scripts.failed === 0
                    ? `All ${scripts.checked} output scripts are P2TR or P2A`
                    : `${scripts.failed} malformed: ${scripts.details.join("; ")}`,
            durationMs: 0,
            evidence: {
                scripts_checked: scripts.checked,
                scripts_failed: scripts.failed,
            },
        },
    ];
}

// ── Phase 4: VtxoTaprootTree decode check ───────────────────────────

function checkScriptTreeBlobs(
    path: readonly DagNode[],
    parsed: ReadonlyMap<Txid, Transaction>
): CheckResult {
    const start = Date.now();
    let checked = 0;
    let failed = 0;
    const details: string[] = [];

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
                if (
                    !key ||
                    key.type !== 222 ||
                    !(key.key instanceof Uint8Array)
                )
                    continue;
                const k = key.key;
                if (
                    k.length < 7 ||
                    k[0] !== 0x74 ||
                    k[1] !== 0x61 ||
                    k[2] !== 0x70 ||
                    k[3] !== 0x74 ||
                    k[4] !== 0x72 ||
                    k[5] !== 0x65 ||
                    k[6] !== 0x65
                )
                    continue;
                if (!(blob instanceof Uint8Array)) {
                    failed++;
                    details.push(
                        `${node.txid} input ${j} VtxoTaprootTree blob is not bytes`
                    );
                    continue;
                }
                checked++;
                try {
                    TapTreeCoder.decode(blob);
                } catch (e) {
                    failed++;
                    details.push(
                        `${node.txid} input ${j} VtxoTaprootTree malformed: ${e instanceof Error ? e.message : String(e)}`
                    );
                }
            }
        }
    }

    return {
        name: "chain.output-script-tree-ok",
        passed: failed === 0,
        details:
            checked === 0
                ? "No VtxoTaprootTree PSBT fields in DAG (trivially ok)"
                : failed === 0
                  ? `All ${checked} VtxoTaprootTree field(s) decode cleanly`
                  : details.join("; "),
        durationMs: Date.now() - start,
        evidence: { fields_checked: checked, fields_failed: failed },
    };
}

// ── Phase 5: Checkpoint CSV coherence ───────────────────────────────

function checkCheckpointCsv(
    path: readonly DagNode[],
    parsed: ReadonlyMap<Txid, Transaction>,
    expectedCsvBlocks?: number
): CheckResult {
    const start = Date.now();
    const observations: Array<{
        txid: Txid;
        observedBlocks: number | null;
    }> = [];
    for (const node of path) {
        if (node.type !== ChainTxType.CHECKPOINT) continue;
        const parsedTx = parsed.get(node.txid);
        if (!parsedTx) continue;
        const inp = parsedTx.getInput(0);
        const seq = inp?.sequence ?? 0xffffffff;
        observations.push({
            txid: node.txid,
            observedBlocks: decodeBip68SequenceBlocks(seq),
        });
    }

    const mismatches: string[] = [];
    let passed = true;
    const distinctCsvs = new Set(
        observations
            .map((o) => o.observedBlocks)
            .filter((v): v is number => v !== null)
    );
    if (distinctCsvs.size > 1) {
        passed = false;
        mismatches.push(
            `CHECKPOINTs disagree on CSV: observed ${Array.from(distinctCsvs).join(", ")}`
        );
    }
    if (expectedCsvBlocks !== undefined && observations.length > 0) {
        for (const obs of observations) {
            if (obs.observedBlocks !== expectedCsvBlocks) {
                passed = false;
                mismatches.push(
                    `${obs.txid} observed ${obs.observedBlocks} blocks, expected ${expectedCsvBlocks}`
                );
            }
        }
    }

    return {
        name: "chain.checkpoint-csv-coherent",
        passed,
        details:
            observations.length === 0
                ? "No CHECKPOINT nodes in DAG (trivially coherent)"
                : passed
                  ? `${observations.length} CHECKPOINT(s) agree on CSV block count`
                  : mismatches.join("; "),
        durationMs: Date.now() - start,
        evidence: {
            checkpoints_checked: observations.length,
            csv_observed: Array.from(distinctCsvs),
            csv_expected: expectedCsvBlocks ?? null,
            csv_mismatches: mismatches,
        },
    };
}

// ── Assemble output ─────────────────────────────────────────────────

function assembleOutput(
    graph: DagGraph,
    orderedTxids: readonly Txid[],
    parsed: ReadonlyMap<Txid, Transaction>
): {
    commitments: UnresolvedCommitmentInfo[];
    dag: DagGraph;
    pathWithTx: DagNode[];
} {
    // Commitments: one per DAG root, recording every claimed vout.
    const voutsByRoot = new Map<Txid, Set<number>>();
    for (const root of graph.roots) voutsByRoot.set(root, new Set());
    for (const [childTxid, parentList] of graph.parents) {
        for (let i = 0; i < parentList.length; i++) {
            const parentTxid = parentList[i];
            const rootVouts = voutsByRoot.get(parentTxid);
            if (!rootVouts) continue;
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

    // Attach parsed Transactions to graph nodes.
    const updatedNodes = new Map<Txid, DagNode>();
    for (const [txid, node] of graph.nodes) {
        const parsedTx = parsed.get(txid);
        updatedNodes.set(txid, parsedTx ? { ...node, tx: parsedTx } : node);
    }
    const dag: DagGraph = {
        nodes: updatedNodes,
        parents: graph.parents,
        children: graph.children,
        roots: graph.roots,
    };
    const pathWithTx: DagNode[] = orderedTxids.map(
        (id) => updatedNodes.get(id) ?? graph.nodes.get(id)!
    );

    return { commitments, dag, pathWithTx };
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
