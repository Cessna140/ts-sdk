import type { UnilateralExitBundle } from "./types";

/**
 * Storage-adapter interface for persisting unilateral-exit bundles.
 * Mirrors the SDK's existing repository pattern
 * (`src/repositories/walletRepository.ts`).
 */
export interface ExitDataRepository {
    saveExitBundle(bundle: UnilateralExitBundle): Promise<void>;
    getExitBundle(vtxoId: string): Promise<UnilateralExitBundle | null>;
    listExitBundles(): Promise<
        readonly { vtxoId: string; capturedAt: string }[]
    >;
    deleteExitBundle(vtxoId: string): Promise<void>;
    pruneExpired(currentBlockHeight: number): Promise<number>;
}

/**
 * In-memory implementation. Production wallets should use an
 * IndexedDB/SQLite-backed adapter; this ships for unit tests and the
 * P6 live-regtest exit-cycle e2e. Stub.
 */
export class InMemoryExitDataRepository implements ExitDataRepository {
    private store = new Map<string, UnilateralExitBundle>();

    async saveExitBundle(bundle: UnilateralExitBundle): Promise<void> {
        this.store.set(bundle.vtxoId, bundle);
    }

    async getExitBundle(vtxoId: string): Promise<UnilateralExitBundle | null> {
        return this.store.get(vtxoId) ?? null;
    }

    async listExitBundles(): Promise<
        readonly { vtxoId: string; capturedAt: string }[]
    > {
        return Array.from(this.store.values()).map((b) => ({
            vtxoId: b.vtxoId,
            capturedAt: b.capturedAt,
        }));
    }

    async deleteExitBundle(vtxoId: string): Promise<void> {
        this.store.delete(vtxoId);
    }

    async pruneExpired(currentBlockHeight: number): Promise<number> {
        let pruned = 0;
        for (const [id, bundle] of this.store) {
            if (bundle.batchExpiryHeight < currentBlockHeight) {
                this.store.delete(id);
                pruned++;
            }
        }
        return pruned;
    }
}
