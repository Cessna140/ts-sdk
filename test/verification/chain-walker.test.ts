import { describe, expect, it } from "vitest";

import {
    walkChain,
    MAX_DAG_NODES,
    makeDagAdapter,
    buildDag,
} from "../../src/verification/chain-walker";
import { ChainTxType } from "../../src/providers/indexer";
import { MalformedChainError } from "../../src/verification/errors";
import { txidFromString } from "../../src/verification/types";
import {
    buildCycleChain,
    buildMockChain,
    buildMockMultiRootChain,
    buildOrphanChain,
    buildSelfLoopChain,
    buildTooLargeChain,
    makeMockIndexerProvider,
} from "./helpers";

describe("chain walker / buildDag", () => {
    describe("happy paths", () => {
        it("F1 single-root linear chain: 6 checks all pass", async () => {
            const fx = buildMockChain({ depth: 2 });
            const indexer = makeMockIndexerProvider({
                vtxoChain: fx.vtxoChain,
                virtualTxs: fx.virtualTxs,
            });
            const out = await walkChain({
                vtxo: fx.leaf,
                indexerProvider: indexer,
            });
            expect(out.checks).toHaveLength(9);
            for (const c of out.checks) {
                expect(c.passed, `${c.name}: ${c.details}`).toBe(true);
            }
            expect(out.dag.roots).toHaveLength(1);
            expect(out.dag.nodes.size).toBe(3); // commitment + 2 tree txs
        });

        it("F2 multi-root DAG: both roots emerge, path-complete passes", async () => {
            const fx = buildMockMultiRootChain();
            const indexer = makeMockIndexerProvider({
                vtxoChain: fx.vtxoChain,
                virtualTxs: fx.virtualTxs,
            });
            const out = await walkChain({
                vtxo: fx.leaf,
                indexerProvider: indexer,
            });
            expect(out.dag.roots).toHaveLength(2);
            const pathComplete = out.checks.find(
                (c) => c.name === "chain.path-complete"
            );
            expect(pathComplete?.passed).toBe(true);
            expect(pathComplete?.evidence?.roots_count).toBe(2);
        });
    });

    describe("structural failures (buildDag throws)", () => {
        it("F6 self-loop throws chain.self-loop", async () => {
            const fx = buildSelfLoopChain();
            const indexer = makeMockIndexerProvider({
                vtxoChain: fx.vtxoChain,
                virtualTxs: [],
            });
            await expect(
                walkChain({ vtxo: fx.leaf, indexerProvider: indexer })
            ).rejects.toMatchObject({
                payload: { code: "chain.self-loop" },
            });
        });

        it("F8 cycle throws chain.cycle", async () => {
            const fx = buildCycleChain();
            const indexer = makeMockIndexerProvider({
                vtxoChain: fx.vtxoChain,
                virtualTxs: [],
            });
            await expect(
                walkChain({ vtxo: fx.leaf, indexerProvider: indexer })
            ).rejects.toMatchObject({
                payload: { code: "chain.cycle" },
            });
        });

        it("F9 orphan throws chain.parent-missing", async () => {
            const fx = buildOrphanChain();
            const indexer = makeMockIndexerProvider({
                vtxoChain: fx.vtxoChain,
                virtualTxs: [],
            });
            await expect(
                walkChain({ vtxo: fx.leaf, indexerProvider: indexer })
            ).rejects.toMatchObject({
                payload: { code: "chain.parent-missing" },
            });
        });

        it("F7 chain exceeding MAX_DAG_NODES throws chain.too-large", async () => {
            const fx = buildTooLargeChain(MAX_DAG_NODES + 1);
            const indexer = makeMockIndexerProvider({
                vtxoChain: fx.vtxoChain,
                virtualTxs: [],
            });
            await expect(
                walkChain({ vtxo: fx.leaf, indexerProvider: indexer })
            ).rejects.toMatchObject({
                payload: { code: "chain.too-large" },
            });
        });

        it("leaf not in chain response throws chain.leaf-missing", async () => {
            const fx = buildMockChain({ depth: 2 });
            const indexer = makeMockIndexerProvider({
                vtxoChain: fx.vtxoChain,
                virtualTxs: fx.virtualTxs,
            });
            const bogusLeaf = { txid: "ff".repeat(32), vout: 0 };
            await expect(
                walkChain({ vtxo: bogusLeaf, indexerProvider: indexer })
            ).rejects.toBeInstanceOf(MalformedChainError);
        });

        it("empty chain response throws chain.empty", async () => {
            const indexer = makeMockIndexerProvider({
                vtxoChain: { chain: [] },
                virtualTxs: [],
            });
            await expect(
                walkChain({
                    vtxo: { txid: "aa".repeat(32), vout: 0 },
                    indexerProvider: indexer,
                })
            ).rejects.toMatchObject({
                payload: { code: "chain.empty" },
            });
        });
    });

    describe("DagAdapter", () => {
        it("commitmentParentedInputs yields every batch-commitment-adjacent input", () => {
            const { graph } = buildDag(
                buildMockMultiRootChain().vtxoChain.chain,
                txidFromString(buildMockMultiRootChain().leaf.txid)
            );
            const adapter = makeDagAdapter(graph);
            const entries = Array.from(adapter.commitmentParentedInputs());
            expect(entries).toHaveLength(2);
            expect(entries.every((e) => e.inputIndex >= 0)).toBe(true);
            expect(new Set(entries.map((e) => e.commitmentTxid)).size).toBe(2);
        });
    });

    describe("provider failure", () => {
        it("indexer error throws ProviderUnavailableError", async () => {
            const indexer = makeMockIndexerProvider({
                vtxoChainError: new Error("502 Bad Gateway"),
            });
            await expect(
                walkChain({
                    vtxo: { txid: "aa".repeat(32), vout: 0 },
                    indexerProvider: indexer,
                })
            ).rejects.toMatchObject({
                payload: { code: "indexer.getVtxoChain-failed" },
            });
        });
    });

    describe("commitments[] multi-vout", () => {
        it("collects every claimed vout per commitment root (bug #8 fix)", async () => {
            const fx = buildMockMultiRootChain();
            const indexer = makeMockIndexerProvider({
                vtxoChain: fx.vtxoChain,
                virtualTxs: fx.virtualTxs,
            });
            const out = await walkChain({
                vtxo: fx.leaf,
                indexerProvider: indexer,
            });
            expect(out.commitments).toHaveLength(2);
            for (const c of out.commitments) {
                expect(c.claimedVouts.length).toBeGreaterThanOrEqual(1);
            }
        });
    });

    describe("value-conservation evidence surfaces skipped txs (bug #5 fix)", () => {
        it("multi-root DAG reports skipped_tx_ids for commitment-parented child", async () => {
            const fx = buildMockMultiRootChain();
            const indexer = makeMockIndexerProvider({
                vtxoChain: fx.vtxoChain,
                virtualTxs: fx.virtualTxs,
            });
            const out = await walkChain({
                vtxo: fx.leaf,
                indexerProvider: indexer,
            });
            const vc = out.checks.find(
                (c) => c.name === "chain.value-conservation"
            );
            // Leaf has two COMMITMENT parents; both amounts unresolved until P5.
            expect(vc?.evidence?.txs_skipped).toBe(1);
            expect(Array.isArray(vc?.evidence?.skipped_tx_ids)).toBe(true);
            expect((vc?.evidence?.skipped_tx_ids as string[]).length).toBe(1);
        });
    });

    describe("tamper detection (CheckResult flips, no throw)", () => {
        it("parent-link tamper flips chain.parent-link only", async () => {
            const fx = buildMockChain({ depth: 2 });
            // Rewrite leaf's spends to a bogus txid; walker still builds
            // DAG (it's a known txid in the chain-by-id map), but then
            // the PSBT's actual input txid won't match.
            const evil = "99".repeat(32);
            // Inject evil into chain so buildDag has it as a parent; make
            // it the leaf's "parent" while the real PSBT still points to
            // the original parent. Then buildDag fabricates an orphan
            // unless we add evil to the chain too.
            const leafEntry = fx.vtxoChain.chain[0];
            const realParent = leafEntry.spends[0];
            leafEntry.spends = [evil];
            fx.vtxoChain.chain.push({
                txid: evil,
                expiresAt: "",
                type: ChainTxType.COMMITMENT,
                spends: [],
            });
            const indexer = makeMockIndexerProvider({
                vtxoChain: fx.vtxoChain,
                virtualTxs: fx.virtualTxs,
            });
            const out = await walkChain({
                vtxo: fx.leaf,
                indexerProvider: indexer,
            });
            const link = out.checks.find((c) => c.name === "chain.parent-link");
            expect(link?.passed).toBe(false);
            // Other checks still ran
            expect(
                out.checks.find((c) => c.name === "chain.fetched")?.passed
            ).toBe(true);
            expect(realParent).toBeTruthy(); // sanity
        });
    });
});
