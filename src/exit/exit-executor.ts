import type { OnchainProvider } from "../providers/onchain";
import type { ExitDataRepository } from "./exit-data-store";
import type { UnilateralExitBundle } from "./types";

export interface ExitExecutionStep {
    readonly name: string;
    readonly succeeded: boolean;
    readonly details?: string;
    readonly durationMs: number;
}

export interface ExitExecutionResult {
    readonly broadcasted: readonly string[];
    readonly steps: readonly ExitExecutionStep[];
    readonly errors: readonly { code: string; message: string }[];
}

export interface ExecuteUnilateralExitInput {
    readonly vtxoId: string;
    readonly repository: ExitDataRepository;
    readonly onchainProvider: OnchainProvider;
    readonly signal?: AbortSignal;
}

/**
 * Executes a unilateral exit using only locally-stored bundle data +
 * an on-chain provider. Never contacts the ASP's IndexerService.
 * Never throws — returns a typed {@link ExitExecutionResult} with
 * per-step trace + structured errors (mirrors verifier partial-failure
 * discipline).
 */
export async function executeUnilateralExit(
    input: ExecuteUnilateralExitInput
): Promise<ExitExecutionResult> {
    const { vtxoId, repository, onchainProvider, signal } = input;
    const broadcasted: string[] = [];
    const steps: ExitExecutionStep[] = [];
    const errors: Array<{ code: string; message: string }> = [];

    // Step 1: Load bundle.
    const bundle = await loadBundle(vtxoId, repository, steps, errors);
    if (!bundle) return { broadcasted, steps, errors };

    // Step 2: Verify commitments still unspent.
    const unspent = await verifyCommitmentsUnspent(
        bundle,
        onchainProvider,
        steps,
        errors
    );
    if (!unspent) return { broadcasted, steps, errors };

    // Step 3: Broadcast tree transactions in schedule order.
    await broadcastTreeTransactions(
        bundle,
        onchainProvider,
        signal,
        broadcasted,
        steps,
        errors
    );

    return { broadcasted, steps, errors };
}

// ── Step 1: Load bundle ─────────────────────────────────────────────

async function loadBundle(
    vtxoId: string,
    repository: ExitDataRepository,
    steps: ExitExecutionStep[],
    errors: Array<{ code: string; message: string }>
): Promise<UnilateralExitBundle | null> {
    const start = Date.now();
    const bundle = await repository.getExitBundle(vtxoId);
    if (!bundle) {
        steps.push({
            name: "load-bundle",
            succeeded: false,
            details: `No exit bundle found for ${vtxoId}`,
            durationMs: Date.now() - start,
        });
        errors.push({
            code: "exit.bundle-not-found",
            message: `No exit bundle stored for VTXO ${vtxoId}`,
        });
        return null;
    }
    steps.push({
        name: "load-bundle",
        succeeded: true,
        details: `Loaded bundle with ${bundle.transactionPath.length} tx(s)`,
        durationMs: Date.now() - start,
    });
    return bundle;
}

// ── Step 2: Verify commitments unspent ──────────────────────────────

async function verifyCommitmentsUnspent(
    bundle: UnilateralExitBundle,
    onchain: OnchainProvider,
    steps: ExitExecutionStep[],
    errors: Array<{ code: string; message: string }>
): Promise<boolean> {
    const start = Date.now();
    for (const c of bundle.commitments) {
        try {
            const outspends = await onchain.getTxOutspends(c.txid);
            if (
                Array.isArray(outspends) &&
                c.vout < outspends.length &&
                outspends[c.vout].spent
            ) {
                steps.push({
                    name: "verify-unspent",
                    succeeded: false,
                    details: `Commitment ${c.txid} vout ${c.vout} already spent`,
                    durationMs: Date.now() - start,
                });
                errors.push({
                    code: "exit.commitment-already-spent",
                    message: `Commitment ${c.txid}:${c.vout} is spent — exit path is dead`,
                });
                return false;
            }
        } catch (e) {
            steps.push({
                name: "verify-unspent",
                succeeded: false,
                details: `Failed to check ${c.txid}: ${e instanceof Error ? e.message : String(e)}`,
                durationMs: Date.now() - start,
            });
            errors.push({
                code: "exit.provider-error",
                message: `getTxOutspends(${c.txid}) failed`,
            });
            return false;
        }
    }
    steps.push({
        name: "verify-unspent",
        succeeded: true,
        details: `All ${bundle.commitments.length} commitment(s) still unspent`,
        durationMs: Date.now() - start,
    });
    return true;
}

// ── Step 3: Broadcast tree transactions ─────────────────────────────

async function broadcastTreeTransactions(
    bundle: UnilateralExitBundle,
    onchain: OnchainProvider,
    signal: AbortSignal | undefined,
    broadcasted: string[],
    steps: ExitExecutionStep[],
    errors: Array<{ code: string; message: string }>
): Promise<void> {
    // Flatten all schedule entries and sort by broadcast order.
    const ordered = bundle.broadcastSchedule
        .flatMap((s) => s.entries)
        .sort((a, b) => a.broadcastOrder - b.broadcastOrder);

    const txByTxid = new Map(
        bundle.transactionPath.map((e) => [e.txid, e.rawTxHex])
    );

    for (const entry of ordered) {
        if (signal?.aborted) {
            errors.push({
                code: "exit.aborted",
                message: "Exit aborted via signal",
            });
            return;
        }

        const start = Date.now();
        const rawHex = txByTxid.get(entry.txid);
        if (!rawHex) {
            steps.push({
                name: `broadcast-${entry.txid}`,
                succeeded: false,
                details: `No raw tx hex found in bundle`,
                durationMs: Date.now() - start,
            });
            errors.push({
                code: "exit.missing-tx",
                message: `Bundle has no raw hex for ${entry.txid}`,
            });
            continue;
        }

        // Idempotency: skip if already confirmed.
        try {
            const status = await onchain.getTxStatus(entry.txid);
            if (status.confirmed) {
                steps.push({
                    name: `broadcast-${entry.txid}`,
                    succeeded: true,
                    details: `Already confirmed at height ${status.blockHeight} — skipped`,
                    durationMs: Date.now() - start,
                });
                broadcasted.push(entry.txid);
                continue;
            }
        } catch {
            // getTxStatus failure is expected for unbroadcast txs.
        }

        // Broadcast.
        try {
            await onchain.broadcastTransaction(rawHex);
            broadcasted.push(entry.txid);
            steps.push({
                name: `broadcast-${entry.txid}`,
                succeeded: true,
                details: `Broadcast successful`,
                durationMs: Date.now() - start,
            });
        } catch (e) {
            steps.push({
                name: `broadcast-${entry.txid}`,
                succeeded: false,
                details: `Broadcast failed: ${e instanceof Error ? e.message : String(e)}`,
                durationMs: Date.now() - start,
            });
            errors.push({
                code: "exit.broadcast-failed",
                message: `Failed to broadcast ${entry.txid}: ${e instanceof Error ? e.message : String(e)}`,
            });
            // Continue with remaining txs — partial exit is better
            // than no exit.
        }
    }
}
