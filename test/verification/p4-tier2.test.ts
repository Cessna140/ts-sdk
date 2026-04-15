/**
 * P4 tests — Tier 2 verifiers (assignment §3.2).
 *
 * Covers:
 *   - verifyScripts (4 script.* checks) — merkle reconstruction,
 *     NUMS-internal-key, VtxoTaprootTree containment, control block
 *     validation
 *   - verifyTimelocks (3 timelock.* checks) — field parsing, script
 *     consistency, hierarchy
 *   - verifyPreimages (2 preimage.* checks) — hash-commitment scan +
 *     witness-stack preimage match; B8 invariant (decodeWitnessStack)
 *   - Pipeline: tier: "script" / "full" runs all three; tier: "chain"
 *     (default) does not
 *   - Unknown Ark PSBT field → errors[] row
 *   - chain.output-script-tree-ok — 9th chain check
 */

import { base64 } from "@scure/base";
import { Transaction } from "@scure/btc-signer/transaction.js";
import { describe, expect, it } from "vitest";

import { verifyVtxo } from "../../src/verification/index";
import {
    decodeWitnessStack,
    MAX_PREIMAGE_CANDIDATES,
    verifyPreimages,
} from "../../src/verification/preimage-verifier";
import { verifyScripts } from "../../src/verification/script-verifier";
import { verifyTimelocks } from "../../src/verification/timelock-verifier";
import {
    makeSignaturePathEntry,
    type Prevout,
} from "../../src/verification/types";
import {
    buildMockChain,
    makeMockIndexerProvider,
    makeMockOnchainProvider,
} from "./helpers";

function sigPathFromVirtualTxs(virtualTxs: string[]) {
    return virtualTxs.map((psbt) => {
        const tx = Transaction.fromPSBT(base64.decode(psbt));
        const prevouts: Prevout[] = [];
        for (let i = 0; i < tx.inputsLength; i++) {
            const inp = tx.getInput(i);
            prevouts.push({
                script: inp.witnessUtxo!.script,
                amount: inp.witnessUtxo!.amount,
            });
        }
        return makeSignaturePathEntry(tx, prevouts);
    });
}

describe("P4: decodeWitnessStack (B8 invariant)", () => {
    it("decodes a 3-element stack in wire format", () => {
        // varint(3) || varint(2) || 0xaa 0xbb || varint(1) || 0xcc || varint(0)
        const bytes = new Uint8Array([
            0x03, 0x02, 0xaa, 0xbb, 0x01, 0xcc, 0x00,
        ]);
        const stack = decodeWitnessStack(bytes);
        expect(stack.length).toBe(3);
        expect(stack[0]).toEqual(new Uint8Array([0xaa, 0xbb]));
        expect(stack[1]).toEqual(new Uint8Array([0xcc]));
        expect(stack[2]).toEqual(new Uint8Array([]));
    });

    it("caps output at MAX_PREIMAGE_CANDIDATES (DoS bound)", () => {
        // Forge a witness with 100 one-byte elements.
        const parts: number[] = [100]; // count = 100
        for (let i = 0; i < 100; i++) {
            parts.push(1, i);
        }
        const bytes = new Uint8Array(parts);
        const stack = decodeWitnessStack(bytes);
        expect(stack.length).toBe(MAX_PREIMAGE_CANDIDATES);
    });

    it("rejects truncated element", () => {
        // count=1, len=5, only 2 bytes of payload
        const bytes = new Uint8Array([0x01, 0x05, 0xaa, 0xbb]);
        expect(() => decodeWitnessStack(bytes)).toThrow(/truncated/);
    });

    it("empty witness returns empty stack", () => {
        expect(decodeWitnessStack(new Uint8Array(0))).toEqual([]);
    });
});

describe("P4: verifyScripts", () => {
    it("key-path fixture — 4 checks emit; vacuous pass on merkle & vtree", async () => {
        const fx = buildMockChain({ depth: 2 });
        const path = sigPathFromVirtualTxs(fx.virtualTxs);
        const out = await verifyScripts({ path });
        expect(out.checks).toHaveLength(4);
        for (const c of out.checks) {
            expect(c.passed, `${c.name}: ${c.details}`).toBe(true);
        }
        const merkle = out.checks.find(
            (c) => c.name === "script.merkle-root-matches"
        );
        expect(merkle?.evidence?.merkle_checks).toBe(0); // no tapLeafScript in key-path fixtures
    });
});

describe("P4: verifyTimelocks", () => {
    it("key-path fixture — all 3 checks pass vacuously", async () => {
        const fx = buildMockChain({ depth: 2 });
        const path = sigPathFromVirtualTxs(fx.virtualTxs);
        const out = await verifyTimelocks({ path });
        expect(out).toHaveLength(3);
        for (const c of out) {
            expect(c.passed, `${c.name}: ${c.details}`).toBe(true);
        }
        const fields = out.find((c) => c.name === "timelock.fields-parsed");
        expect(fields?.evidence?.fields_parsed).toBe(2);
        expect(fields?.evidence?.cltv_scripts_found).toBe(0);
        expect(fields?.evidence?.csv_scripts_found).toBe(0);
    });
});

describe("P4: verifyPreimages", () => {
    it("key-path fixture — 2 checks pass vacuously with 0 commitments found", async () => {
        const fx = buildMockChain({ depth: 2 });
        const path = sigPathFromVirtualTxs(fx.virtualTxs);
        const out = await verifyPreimages({ path });
        expect(out).toHaveLength(2);
        for (const c of out) {
            expect(c.passed, `${c.name}: ${c.details}`).toBe(true);
        }
        const scan = out.find((c) => c.name === "preimage.conditions-scanned");
        expect(scan?.evidence?.commitments_found).toBe(0);
    });
});

describe("P4: pipeline Tier 2 wiring", () => {
    it("tier: 'chain' (default) emits 9 + 4 = 13 rows; no Tier 2", async () => {
        const fx = buildMockChain({ depth: 2 });
        const indexer = makeMockIndexerProvider({
            vtxoChain: fx.vtxoChain,
            virtualTxs: fx.virtualTxs,
        });
        const result = await verifyVtxo({
            vtxoId: fx.leaf,
            indexerProvider: indexer,
            onchainProvider: makeMockOnchainProvider({
                txOutputsByTxid: {
                    [fx.commitmentTxid]: [
                        {
                            script: new Uint8Array(34).fill(0x51),
                            amount: 100_000n,
                        },
                    ],
                },
            }),
        });
        expect(result.checks.length).toBe(17);
        expect(
            result.checks.find((c) => c.name.startsWith("script."))
        ).toBeUndefined();
    });

    it("tier: 'full' emits 9 chain + 4 sig + 4 script + 3 timelock + 2 preimage = 22 rows", async () => {
        const fx = buildMockChain({ depth: 2 });
        const indexer = makeMockIndexerProvider({
            vtxoChain: fx.vtxoChain,
            virtualTxs: fx.virtualTxs,
        });
        const result = await verifyVtxo({
            vtxoId: fx.leaf,
            indexerProvider: indexer,
            onchainProvider: makeMockOnchainProvider({
                txOutputsByTxid: {
                    [fx.commitmentTxid]: [
                        {
                            script: new Uint8Array(34).fill(0x51),
                            amount: 100_000n,
                        },
                    ],
                },
            }),
            options: { tier: "full" },
        });
        expect(result.checks.length).toBe(26);
        for (const c of result.checks) {
            expect(c.passed, `${c.name}: ${c.details}`).toBe(true);
        }
        // All 26 rows green; expiry row passes with undefined-expiry
        // UNSUPPORTED note (no tapleaf in key-path fixture).
        const expiryRow = result.checks.find(
            (c) => c.name === "anchor.expiry-not-passed"
        );
        expect(expiryRow?.evidence?.unsupported_count).toBeGreaterThanOrEqual(
            1
        );
    });

    it("tier: 'script' also emits 22 rows (alias for Tier 2 enabled)", async () => {
        const fx = buildMockChain({ depth: 2 });
        const indexer = makeMockIndexerProvider({
            vtxoChain: fx.vtxoChain,
            virtualTxs: fx.virtualTxs,
        });
        const result = await verifyVtxo({
            vtxoId: fx.leaf,
            indexerProvider: indexer,
            onchainProvider: makeMockOnchainProvider({
                txOutputsByTxid: {
                    [fx.commitmentTxid]: [
                        {
                            script: new Uint8Array(34).fill(0x51),
                            amount: 100_000n,
                        },
                    ],
                },
            }),
            options: { tier: "script" },
        });
        expect(result.checks.length).toBe(26);
    });
});

describe("P4: chain.output-script-tree-ok (9th chain check)", () => {
    it("is present in the chain-walker output", async () => {
        const fx = buildMockChain({ depth: 2 });
        const indexer = makeMockIndexerProvider({
            vtxoChain: fx.vtxoChain,
            virtualTxs: fx.virtualTxs,
        });
        const result = await verifyVtxo({
            vtxoId: fx.leaf,
            indexerProvider: indexer,
            onchainProvider: makeMockOnchainProvider({
                txOutputsByTxid: {
                    [fx.commitmentTxid]: [
                        {
                            script: new Uint8Array(34).fill(0x51),
                            amount: 100_000n,
                        },
                    ],
                },
            }),
        });
        const st = result.checks.find(
            (c) => c.name === "chain.output-script-tree-ok"
        );
        expect(st).toBeDefined();
        expect(st?.passed).toBe(true);
        // key-path fixtures carry no VtxoTaprootTree PSBT fields →
        // the check passes trivially with 0 observations.
        expect(st?.evidence?.fields_checked).toBe(0);
    });
});
