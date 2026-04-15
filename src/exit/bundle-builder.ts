import type { DagGraph } from "../verification/chain-walker";
import type { PerPathSchedule } from "../verification/types";
import type { UnilateralExitBundle } from "./types";

/**
 * Builds a per-path broadcast schedule from a DAG, accumulating per-hop
 * CSV delays down each root→leaf path. This is the ONLY way to construct
 * a {@link PerPathSchedule} — bug B10 from v1 self-review, where the v1
 * bundle builder used a global `max(confirmationHeight) + i` offset that
 * ignored per-path CSV in multi-root bundles.
 *
 * Stub — implementation lands in P6.
 */
export function scheduleFromDag(
    _dag: DagGraph,
    _csvDelays: ReadonlyMap<string, number>
): readonly PerPathSchedule[] {
    throw new Error("scheduleFromDag: not implemented until P6");
}

export async function buildExitBundleFromVtxo(
    _vtxoId: string,
    _indexerProvider: unknown,
    _onchainProvider: unknown
): Promise<UnilateralExitBundle> {
    throw new Error("buildExitBundleFromVtxo: not implemented until P6");
}
