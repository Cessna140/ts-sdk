/**
 * P6 tests — §3.3 sovereign unilateral exit.
 *
 * Covers:
 *   - scheduleFromDag: single-root + multi-root DAGs
 *   - executeUnilateralExit: happy path, bundle-not-found,
 *     commitment-spent, broadcast failure, idempotency
 *   - InMemoryExitDataRepository: save/get/delete round-trip
 */

import { describe, expect, it, vi } from "vitest";

import { scheduleFromDag } from "../../src/exit/bundle-builder";
import { executeUnilateralExit } from "../../src/exit/exit-executor";
import { InMemoryExitDataRepository } from "../../src/exit/exit-data-store";
import type { UnilateralExitBundle } from "../../src/exit/types";
import type { DagGraph } from "../../src/verification/chain-walker";
import type { Txid, BlockHeight } from "../../src/verification/types";
import {
    txidFromString,
    blockHeightFromRelativeDelay,
} from "../../src/verification/types";
import { ChainTxType } from "../../src/providers/indexer";

function fakeTxid(n: number): Txid {
    return txidFromString(n.toString(16).padStart(64, "0"));
}

function fakeGraph(opts: {
    roots: Txid[];
    children: Array<[Txid, Txid[]]>;
}): DagGraph {
    const nodes = new Map<
        Txid,
        { txid: Txid; type: ChainTxType; chainTx: unknown }
    >();
    for (const root of opts.roots) {
        nodes.set(root, {
            txid: root,
            type: ChainTxType.COMMITMENT,
            chainTx: {},
        });
    }
    const childrenMap = new Map<Txid, Txid[]>();
    const parentsMap = new Map<Txid, Txid[]>();
    for (const [parent, kids] of opts.children) {
        childrenMap.set(parent, kids);
        if (!nodes.has(parent)) {
            nodes.set(parent, {
                txid: parent,
                type: ChainTxType.TREE,
                chainTx: {},
            });
        }
        for (const kid of kids) {
            if (!nodes.has(kid)) {
                nodes.set(kid, {
                    txid: kid,
                    type: ChainTxType.TREE,
                    chainTx: {},
                });
            }
            const prev = parentsMap.get(kid) ?? [];
            prev.push(parent);
            parentsMap.set(kid, prev);
        }
    }
    return {
        nodes,
        parents: parentsMap,
        children: childrenMap,
        roots: opts.roots,
    };
}

function fakeBundle(
    overrides?: Partial<UnilateralExitBundle>
): UnilateralExitBundle {
    const txid1 = fakeTxid(0xaa);
    const txid2 = fakeTxid(0xbb);
    return {
        vtxoId: "test:0",
        commitments: [
            {
                txid: fakeTxid(0xcc),
                vout: 0,
                batchScript: new Uint8Array(34),
                batchAmount: 100_000n,
                batchExpiryHeight: 1000 as BlockHeight,
            },
        ],
        transactionPath: [
            { txid: txid1, rawTxHex: "deadbeef01", pathIndex: 0 },
            { txid: txid2, rawTxHex: "deadbeef02", pathIndex: 0 },
        ],
        claimTemplate: {
            outputScriptHex: "5120" + "aa".repeat(32),
            feeRate: 1,
            keyDerivationPath: "m/86'/1'/0'/0/0",
        },
        csvDelayBlocks: 144,
        batchExpiryHeight: 1000 as BlockHeight,
        broadcastSchedule: [
            {
                pathIndex: 0,
                entries: [
                    {
                        txid: txid1,
                        earliestBlock: 110 as BlockHeight,
                        broadcastOrder: 0,
                    },
                    {
                        txid: txid2,
                        earliestBlock: 254 as BlockHeight,
                        broadcastOrder: 1,
                    },
                ],
            },
        ],
        capturedAt: new Date().toISOString(),
        ...overrides,
    };
}

describe("P6: scheduleFromDag", () => {
    it("single-root DAG produces one schedule with correct block heights", () => {
        const root = fakeTxid(1);
        const child = fakeTxid(2);
        const leaf = fakeTxid(3);
        const graph = fakeGraph({
            roots: [root],
            children: [
                [root, [child]],
                [child, [leaf]],
            ],
        });
        const csvDelays = new Map<Txid, number>([
            [child, 10],
            [leaf, 20],
        ]);
        const confirmHeights = new Map<Txid, number>([[root, 100]]);

        const schedules = scheduleFromDag(graph, csvDelays, confirmHeights);

        expect(schedules).toHaveLength(1);
        expect(schedules[0].pathIndex).toBe(0);
        expect(schedules[0].entries).toHaveLength(2);

        // child: confirmHeight(100) + csv(10) = 110
        expect(schedules[0].entries[0].txid).toBe(child);
        expect(Number(schedules[0].entries[0].earliestBlock)).toBe(110);

        // leaf: confirmHeight(100) + csv(10) + csv(20) = 130
        expect(schedules[0].entries[1].txid).toBe(leaf);
        expect(Number(schedules[0].entries[1].earliestBlock)).toBe(130);
    });

    it("multi-root DAG produces independent schedules per root", () => {
        const root1 = fakeTxid(1);
        const root2 = fakeTxid(2);
        const child1 = fakeTxid(3);
        const child2 = fakeTxid(4);
        const graph = fakeGraph({
            roots: [root1, root2],
            children: [
                [root1, [child1]],
                [root2, [child2]],
            ],
        });
        const csvDelays = new Map<Txid, number>([
            [child1, 10],
            [child2, 50],
        ]);
        const confirmHeights = new Map<Txid, number>([
            [root1, 100],
            [root2, 200],
        ]);

        const schedules = scheduleFromDag(graph, csvDelays, confirmHeights);
        expect(schedules).toHaveLength(2);

        // root1 path: 100 + 10 = 110
        expect(Number(schedules[0].entries[0].earliestBlock)).toBe(110);
        // root2 path: 200 + 50 = 250
        expect(Number(schedules[1].entries[0].earliestBlock)).toBe(250);
    });
});

describe("P6: executeUnilateralExit", () => {
    it("happy path — all steps succeed", async () => {
        const repo = new InMemoryExitDataRepository();
        const bundle = fakeBundle();
        await repo.saveExitBundle(bundle);

        const onchain = {
            getTxOutspends: vi.fn(async () => [{ spent: false, txid: "" }]),
            getTxStatus: vi.fn(async () => ({ confirmed: false })),
            broadcastTransaction: vi.fn(async () => ""),
            getChainTip: vi.fn(async () => ({
                height: 300,
                time: 0,
                hash: "",
            })),
            getCoins: vi.fn(async () => []),
            getFeeRate: vi.fn(async () => 1),
            getTransactions: vi.fn(async () => []),
            watchAddresses: vi.fn(async () => () => {}),
            getTxOutputs: vi.fn(async () => []),
        };

        const result = await executeUnilateralExit({
            vtxoId: "test:0",
            repository: repo,
            onchainProvider: onchain,
        });

        expect(result.errors).toHaveLength(0);
        expect(result.broadcasted).toHaveLength(2);
        expect(result.steps.every((s) => s.succeeded)).toBe(true);
    });

    it("bundle not found — structured error, no throw", async () => {
        const repo = new InMemoryExitDataRepository();
        const onchain = {} as any;

        const result = await executeUnilateralExit({
            vtxoId: "missing:0",
            repository: repo,
            onchainProvider: onchain,
        });

        expect(result.errors).toHaveLength(1);
        expect(result.errors[0].code).toBe("exit.bundle-not-found");
        expect(result.broadcasted).toHaveLength(0);
    });

    it("commitment already spent — structured error", async () => {
        const repo = new InMemoryExitDataRepository();
        const bundle = fakeBundle();
        await repo.saveExitBundle(bundle);

        const onchain = {
            getTxOutspends: vi.fn(async () => [
                { spent: true, txid: "spender" },
            ]),
            getCoins: vi.fn(async () => []),
            getFeeRate: vi.fn(async () => 1),
            broadcastTransaction: vi.fn(async () => ""),
            getTransactions: vi.fn(async () => []),
            getTxStatus: vi.fn(async () => ({ confirmed: false })),
            getChainTip: vi.fn(async () => ({
                height: 300,
                time: 0,
                hash: "",
            })),
            watchAddresses: vi.fn(async () => () => {}),
            getTxOutputs: vi.fn(async () => []),
        };

        const result = await executeUnilateralExit({
            vtxoId: "test:0",
            repository: repo,
            onchainProvider: onchain,
        });

        expect(result.errors).toHaveLength(1);
        expect(result.errors[0].code).toBe("exit.commitment-already-spent");
        expect(result.broadcasted).toHaveLength(0);
    });

    it("broadcast failure — error recorded, remaining txs attempted", async () => {
        const repo = new InMemoryExitDataRepository();
        const bundle = fakeBundle();
        await repo.saveExitBundle(bundle);

        let callCount = 0;
        const onchain = {
            getTxOutspends: vi.fn(async () => [{ spent: false, txid: "" }]),
            getTxStatus: vi.fn(async () => ({ confirmed: false })),
            broadcastTransaction: vi.fn(async () => {
                callCount++;
                if (callCount === 1) throw new Error("network error");
                return "";
            }),
            getCoins: vi.fn(async () => []),
            getFeeRate: vi.fn(async () => 1),
            getTransactions: vi.fn(async () => []),
            getChainTip: vi.fn(async () => ({
                height: 300,
                time: 0,
                hash: "",
            })),
            watchAddresses: vi.fn(async () => () => {}),
            getTxOutputs: vi.fn(async () => []),
        };

        const result = await executeUnilateralExit({
            vtxoId: "test:0",
            repository: repo,
            onchainProvider: onchain,
        });

        expect(result.errors).toHaveLength(1);
        expect(result.errors[0].code).toBe("exit.broadcast-failed");
        // Second tx still attempted and succeeded.
        expect(result.broadcasted).toHaveLength(1);
        expect(onchain.broadcastTransaction).toHaveBeenCalledTimes(2);
    });

    it("idempotency — already-confirmed tx skipped", async () => {
        const repo = new InMemoryExitDataRepository();
        const bundle = fakeBundle();
        await repo.saveExitBundle(bundle);

        const txid1 = bundle.transactionPath[0].txid;
        const onchain = {
            getTxOutspends: vi.fn(async () => [{ spent: false, txid: "" }]),
            getTxStatus: vi.fn(async (txid: string) => {
                if (txid === txid1) {
                    return { confirmed: true, blockTime: 0, blockHeight: 150 };
                }
                return { confirmed: false };
            }),
            broadcastTransaction: vi.fn(async () => ""),
            getCoins: vi.fn(async () => []),
            getFeeRate: vi.fn(async () => 1),
            getTransactions: vi.fn(async () => []),
            getChainTip: vi.fn(async () => ({
                height: 300,
                time: 0,
                hash: "",
            })),
            watchAddresses: vi.fn(async () => () => {}),
            getTxOutputs: vi.fn(async () => []),
        };

        const result = await executeUnilateralExit({
            vtxoId: "test:0",
            repository: repo,
            onchainProvider: onchain,
        });

        expect(result.errors).toHaveLength(0);
        expect(result.broadcasted).toHaveLength(2);
        // Only tx2 was actually broadcast; tx1 was skipped.
        expect(onchain.broadcastTransaction).toHaveBeenCalledTimes(1);
    });
});

describe("P6: InMemoryExitDataRepository", () => {
    it("save → get round-trips correctly", async () => {
        const repo = new InMemoryExitDataRepository();
        const bundle = fakeBundle();
        await repo.saveExitBundle(bundle);
        const loaded = await repo.getExitBundle("test:0");
        expect(loaded).not.toBeNull();
        expect(loaded!.vtxoId).toBe("test:0");
        expect(loaded!.transactionPath).toHaveLength(2);
    });

    it("delete removes bundle", async () => {
        const repo = new InMemoryExitDataRepository();
        await repo.saveExitBundle(fakeBundle());
        await repo.deleteExitBundle("test:0");
        expect(await repo.getExitBundle("test:0")).toBeNull();
    });

    it("listExitBundles returns summaries", async () => {
        const repo = new InMemoryExitDataRepository();
        await repo.saveExitBundle(fakeBundle());
        const list = await repo.listExitBundles();
        expect(list).toHaveLength(1);
        expect(list[0].vtxoId).toBe("test:0");
    });

    it("pruneExpired removes expired bundles", async () => {
        const repo = new InMemoryExitDataRepository();
        await repo.saveExitBundle(
            fakeBundle({ batchExpiryHeight: 500 as BlockHeight })
        );
        const pruned = await repo.pruneExpired(600);
        expect(pruned).toBe(1);
        expect(await repo.getExitBundle("test:0")).toBeNull();
    });
});
