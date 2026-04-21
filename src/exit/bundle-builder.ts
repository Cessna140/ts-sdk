import type { IndexerProvider } from "../providers/indexer";
import type { OnchainProvider } from "../providers/onchain";
import type { Outpoint } from "../wallet";
import type { DagGraph, DagNode } from "../verification/chain-walker";
import { walkChain, makeDagAdapter } from "../verification/chain-walker";
import {
    resolveCommitments,
    extractCommitmentTapleafScripts,
    extractCommitmentExpiryHeights,
} from "../verification/anchor-verifier";
import type { BlockHeight, PerPathSchedule, Txid } from "../verification/types";
import {
    blockHeightFromRelativeDelay,
    decodeBip68SequenceBlocks,
} from "../verification/types";
import { ChainTxType } from "../providers/indexer";
import type {
    UnilateralExitBundle,
    ExitPathEntry,
    ClaimTemplate,
} from "./types";
import type { ExitDataRepository } from "./exit-data-store";

/**
 * Builds a per-path broadcast schedule from a DAG by DFS from each
 * commitment root, accumulating CSV delays per hop. This is the ONLY
 * way to construct a {@link PerPathSchedule} — prevents B10 (global
 * offset vulnerability in multi-root bundles).
 */
export function scheduleFromDag(
    dag: DagGraph,
    csvDelays: ReadonlyMap<Txid, number>,
    commitmentConfirmHeights: ReadonlyMap<Txid, number>
): readonly PerPathSchedule[] {
    const schedules: PerPathSchedule[] = [];

    for (let pathIndex = 0; pathIndex < dag.roots.length; pathIndex++) {
        const root = dag.roots[pathIndex];
        const confirmHeight = commitmentConfirmHeights.get(root);
        if (confirmHeight === undefined) continue;

        const entries: Array<{
            txid: Txid;
            earliestBlock: BlockHeight;
            broadcastOrder: number;
        }> = [];

        // DFS from root, accumulating CSV delays.
        let order = 0;
        const stack: Array<{ txid: Txid; accumulatedCsv: number }> = [
            { txid: root, accumulatedCsv: 0 },
        ];

        while (stack.length > 0) {
            const { txid, accumulatedCsv } = stack.pop()!;
            const children = dag.children.get(txid) ?? [];

            for (const childTxid of children) {
                const childCsv = csvDelays.get(childTxid) ?? 0;
                const totalCsv = accumulatedCsv + childCsv;

                entries.push({
                    txid: childTxid,
                    earliestBlock: blockHeightFromRelativeDelay(
                        totalCsv,
                        confirmHeight
                    ),
                    broadcastOrder: order++,
                });

                stack.push({
                    txid: childTxid,
                    accumulatedCsv: totalCsv,
                });
            }
        }

        schedules.push({ pathIndex, entries });
    }

    return schedules;
}

/**
 * Build a complete {@link UnilateralExitBundle} for a VTXO. Uses the
 * verification module's DAG walker and commitment resolver to capture
 * all data needed for a sovereign unilateral exit — no ASP needed
 * after this point.
 */
export async function buildExitBundleFromVtxo(
    vtxoId: Outpoint,
    indexerProvider: IndexerProvider,
    onchainProvider: OnchainProvider,
    claimTemplate: ClaimTemplate
): Promise<UnilateralExitBundle> {
    // Phase 1: Walk the chain and build the DAG.
    const walker = await walkChain({
        vtxo: vtxoId,
        indexerProvider,
    });

    // Phase 2: Resolve commitments for on-chain anchor data.
    const dagAdapter = makeDagAdapter(walker.dag);
    const tapleafMap = extractCommitmentTapleafScripts(
        walker.commitments,
        (txid) => walker.dag.nodes.get(txid)?.tx,
        dagAdapter.commitmentParentedInputs()
    );
    const expiryHeightMap = await extractCommitmentExpiryHeights(
        walker.commitments,
        (txid) => walker.dag.nodes.get(txid)?.tx,
        dagAdapter.commitmentParentedInputs(),
        onchainProvider
    );
    const resolved = await resolveCommitments(
        walker.commitments,
        onchainProvider,
        tapleafMap,
        expiryHeightMap
    );
    if (!resolved.ok) {
        throw new Error(
            `Failed to resolve commitments: ${(resolved as { error: string }).error}`
        );
    }
    const commitments = resolved.value;

    // Phase 3: Extract raw tx hex + CSV delays for each off-chain node.
    const transactionPath: ExitPathEntry[] = [];
    const csvDelays = new Map<Txid, number>();

    for (const node of walker.path) {
        if (node.type === ChainTxType.COMMITMENT) continue;
        if (!node.tx) continue;

        const rawTxHex = extractRawTxHex(node);
        transactionPath.push({
            txid: node.txid,
            rawTxHex,
            pathIndex: 0,
        });

        // Extract CSV from input 0's nSequence.
        const inp = node.tx.getInput(0);
        const seq = inp?.sequence ?? 0xffffffff;
        const csvBlocks = decodeBip68SequenceBlocks(seq);
        if (csvBlocks !== null) {
            csvDelays.set(node.txid, csvBlocks);
        }
    }

    // Phase 4: Get commitment confirmation heights for scheduling.
    const confirmHeights = new Map<Txid, number>();
    for (const c of commitments) {
        const status = await onchainProvider.getTxStatus(c.txid);
        if (status.confirmed) {
            confirmHeights.set(c.txid, status.blockHeight);
        }
    }

    // Phase 5: Build broadcast schedule.
    const broadcastSchedule = scheduleFromDag(
        walker.dag,
        csvDelays,
        confirmHeights
    );

    // Determine overall CSV delay and expiry.
    const maxCsvDelay = Math.max(0, ...Array.from(csvDelays.values()));
    // Expiry is optional — arkd regtest uses seconds-based
    // VtxoTreeExpiry which B9 won't convert to block height.
    // The bundle is still useful for broadcast scheduling.
    const batchExpiryHeight = commitments.find(
        (c) => c.batchExpiryHeight !== undefined
    )?.batchExpiryHeight;

    return {
        vtxoId: `${vtxoId.txid}:${vtxoId.vout}`,
        commitments,
        transactionPath,
        claimTemplate,
        csvDelayBlocks: maxCsvDelay,
        batchExpiryHeight,
        broadcastSchedule,
        capturedAt: new Date().toISOString(),
    };
}

/**
 * Capture exit data for a VTXO and persist it. Convenience wrapper
 * combining {@link buildExitBundleFromVtxo} + repository save.
 *
 * Integration point: call this after receiving new VTXOs from a
 * settlement round. See vtxo-manager.ts line 966 for the hook point.
 */
export async function captureExitData(
    vtxoId: Outpoint,
    indexerProvider: IndexerProvider,
    onchainProvider: OnchainProvider,
    repository: ExitDataRepository,
    claimTemplate: ClaimTemplate
): Promise<void> {
    const bundle = await buildExitBundleFromVtxo(
        vtxoId,
        indexerProvider,
        onchainProvider,
        claimTemplate
    );
    await repository.saveExitBundle(bundle);
}

function extractRawTxHex(node: DagNode): string {
    if (!node.tx) throw new Error(`No parsed tx for ${node.txid}`);
    // Extract the raw transaction bytes from the PSBT.
    try {
        return node.tx.hex;
    } catch {
        // If the tx isn't finalized, extract from PSBT bytes.
        const psbtBytes = node.tx.toPSBT();
        return Buffer.from(psbtBytes).toString("hex");
    }
}
