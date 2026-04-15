import type { CheckResult, CommitmentInfo, Result, Txid } from "./types";

/**
 * Output of the DAG walker. Unlike v1's `ChainWalkerOutput` which carried
 * a linear `path[]` and a singular `batchOutpoint`, this output exposes:
 *
 *   - `dag` — the raw multi-root DAG (nodes, parents, children, roots)
 *   - `path` — topologically sorted (leaf first, commitments last) so
 *     downstream verifiers can always resolve parent data already-parsed
 *   - `commitments` — an array of {@link CommitmentInfo} (one per DAG
 *     root), never a singular field; supports §3.1.1 multi-root semantics
 */
export interface DagWalkerOutput {
    readonly checks: readonly CheckResult[];
    readonly dag: DagGraph;
    readonly path: readonly DagNode[];
    readonly commitments: readonly CommitmentInfo[];
}

export interface DagGraph {
    readonly nodes: ReadonlyMap<Txid, DagNode>;
    readonly parents: ReadonlyMap<Txid, readonly Txid[]>;
    readonly children: ReadonlyMap<Txid, readonly Txid[]>;
    readonly roots: readonly Txid[];
}

export interface DagNode {
    readonly txid: Txid;
    readonly type: "VIRTUAL" | "CHECKPOINT" | "COMMITMENT";
    // Parsed Transaction populated by the walker; undefined for commitment
    // nodes which are on-chain-only and never parsed as PSBT by the
    // indexer response.
    readonly tx?: unknown;
}

/**
 * Adapter exposing DAG-aware iteration utilities that downstream verifiers
 * consume. Keeps the NUMS assertion, MuSig2 aggregate check, and anchor
 * iteration out of the "walk the path linearly and poke the last entry"
 * trap v1 fell into (bug B3 from self-review).
 */
export interface DagAdapter {
    readonly graph: DagGraph;

    /**
     * Yields every input whose parent (via `graph.parents`) is a COMMITMENT
     * node. Every batch-commitment-adjacent input must satisfy the
     * BIP 341 NUMS internal-key assertion and the MuSig2 aggregate check;
     * this iterator is the only API by which those verifiers find them.
     */
    commitmentParentedInputs(): IterableIterator<{
        readonly childTxid: Txid;
        readonly inputIndex: number;
        readonly commitmentTxid: Txid;
    }>;
}

/**
 * Resolves a commitment's (vout, script, amount, expiryHeight). Returns
 * a {@link Result} — callers must handle the error variant; there is no
 * silent vout=0 fallback (bug B7 from v1 self-review).
 */
export type CommitmentResolver = (
    commitmentTxid: Txid
) => Promise<Result<CommitmentInfo, string>>;

/**
 * Stub — implementation lands in P1.
 */
export async function buildDag(
    _chain: unknown,
    _leafTxid: Txid
): Promise<DagWalkerOutput> {
    throw new Error("buildDag: not implemented until P1");
}
