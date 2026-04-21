/**
 * Boltz VHTLC verification — assignment §3.2.3 deliverable.
 *
 * Demonstrates that the verifier recognises Boltz-shape preimage
 * commitments (OP_HASH160 + 20B push) on a real `VHTLC.Script`-built
 * contract, not just our hand-rolled M1 SHA256 fixture.
 */

import { describe, expect, it } from "vitest";

import { verifyVtxo } from "../../src/verification/index";
import { buildBoltzVhtlcFixture } from "./fixtures/boltz-vhtlc";
import { makeMockIndexerProvider, makeMockOnchainProvider } from "./helpers";

describe("§3.2.3 Boltz VHTLC: preimage verifier recognises HASH160 claim", () => {
    it("tier: 'full' pipeline — HASH160 commitment found in claim leaf; multi-leaf taptree validates", async () => {
        const fx = buildBoltzVhtlcFixture();
        const indexer = makeMockIndexerProvider({
            vtxoChain: fx.vtxoChain,
            virtualTxs: fx.virtualTxs,
        });
        const onchain = makeMockOnchainProvider({
            chainTip: {
                height: 50,
                time: 1_700_000_000,
                hash: "00".repeat(32),
            },
            txStatus: {
                [fx.commitmentTxid]: {
                    confirmed: true,
                    blockTime: 1_700_000_000,
                    blockHeight: 10,
                },
            },
            txOutputsByTxid: {
                [fx.commitmentTxid]: [
                    {
                        script: fx.commitmentScript,
                        amount: fx.commitmentAmount,
                    },
                ],
            },
            outspendsByTxid: {
                [fx.commitmentTxid]: [{ spent: false, txid: "" }],
            },
        });
        const result = await verifyVtxo({
            vtxoId: fx.leaf,
            indexerProvider: indexer,
            onchainProvider: onchain,
            options: { tier: "full" },
        });

        // Every row green; surface any errors[] for diagnostic clarity
        // (VHTLC.encode produces a 6-leaf tree whose individual
        // tapscripts may carry sub-fields the script verifier flags as
        // unrecognised — those are UNSUPPORTED, not failures).
        for (const c of result.checks) {
            expect(c.passed, `${c.name}: ${c.details}`).toBe(true);
        }
        // Errors[] entries are acceptable here as long as they are
        // UNSUPPORTED (informational) rather than DATA / NETWORK.
        for (const e of result.errors) {
            expect(e.kind, `unexpected error: ${JSON.stringify(e)}`).toBe(
                "UNSUPPORTED"
            );
        }

        const byName = new Map(result.checks.map((c) => [c.name, c]));

        // §3.2.3 core: HASH160 commitment found in tapleaf scan.
        const preScan = byName.get("preimage.conditions-scanned");
        expect(preScan?.evidence?.commitments_found).toBeGreaterThanOrEqual(1);
        expect(preScan?.evidence?.hash160_commitments).toBeGreaterThanOrEqual(
            1
        );

        // Real VHTLC has 6 tapleaves — multi-leaf merkle path exercised
        // (M1 had a single leaf; this is meaningfully more).
        expect(fx.vhtlc.scripts.length).toBe(6);
        const merkle = byName.get("script.merkle-root-matches");
        expect(merkle?.evidence?.merkle_checks).toBeGreaterThanOrEqual(1);
        expect(merkle?.evidence?.merkle_matched).toBeGreaterThanOrEqual(1);

        // VHTLC uses NUMS internal key (Ark contract convention).
        const nums = byName.get("script.internal-key-is-nums");
        expect(nums?.evidence?.inputs_checked).toBeGreaterThanOrEqual(1);
        expect(nums?.evidence?.inputs_matched).toBeGreaterThanOrEqual(1);

        // VtxoTaprootTree carries the full 6-leaf tree; executed claim
        // leaf is one of them.
        const vtree = byName.get("script.vtxotaprootree-valid");
        expect(vtree?.evidence?.vtxotree_checks).toBeGreaterThanOrEqual(1);
        expect(vtree?.evidence?.vtxotree_matched).toBeGreaterThanOrEqual(1);

        // §3.2.3 preimage matching: the ConditionWitness PSBT field
        // carries the preimage (set during intent construction per
        // src/contracts/handlers/vhtlc.ts:114). The verifier extracts
        // it, hashes it, and compares against the HASH160 commitment
        // found in the claim leaf. This is the "verify that the
        // provided preimage correctly satisfies the hash condition"
        // deliverable.
        const preMatch = byName.get("preimage.hashes-match");
        expect(preMatch?.passed).toBe(true);
        expect(preMatch?.evidence?.preimages_matched).toBeGreaterThanOrEqual(1);
        expect(preMatch?.evidence?.preimages_mismatched).toBe(0);
    });
});
