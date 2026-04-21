import type {
    BlockHeight,
    PerPathSchedule,
    ResolvedCommitmentInfo,
    Txid,
} from "../verification/types";

/**
 * Per-hop entry in the unilateral-exit `transactionPath`. Broadcast order
 * is determined by the {@link PerPathSchedule} rather than this array's
 * order alone — see {@link UnilateralExitBundle.broadcastSchedule}.
 */
export interface ExitPathEntry {
    readonly txid: Txid;
    readonly rawTxHex: string;
    readonly pathIndex: number;
}

export interface ClaimTemplate {
    readonly outputScriptHex: string;
    readonly feeRate: number;
    readonly keyDerivationPath: string;
}

/**
 * The full self-custody exit bundle. Multi-commitment from day one — bug
 * B10 from v1 self-review (broadcastSchedule used a global
 * `max(confirmationHeight) + i` offset) is prevented by requiring the
 * schedule to be built per-path via
 * {@link scheduleFromDag} (no global-offset constructor exists).
 */
export interface UnilateralExitBundle {
    readonly vtxoId: string;
    readonly commitments: readonly ResolvedCommitmentInfo[];
    readonly transactionPath: readonly ExitPathEntry[];
    readonly claimTemplate: ClaimTemplate;
    readonly csvDelayBlocks: number;
    readonly batchExpiryHeight?: BlockHeight;
    readonly broadcastSchedule: readonly PerPathSchedule[];
    readonly capturedAt: string; // ISO-8601
}
