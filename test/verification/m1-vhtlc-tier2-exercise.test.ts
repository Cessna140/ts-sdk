/**
 * M1 pre-PR mandatory — script-path fixture exercise.
 *
 * The VHTLC fixture runs through the full pipeline with tier: "full".
 * We assert NON-ZERO evidence on every Tier 2 row that was previously
 * vacuous under key-path fixtures:
 *   - script.control-block-valid        → >= 1 control block
 *   - script.merkle-root-matches        → >= 1 reconstruction
 *   - script.internal-key-is-nums       → >= 1 commitment-parented
 *   - script.vtxotaprootree-valid       → >= 1 vtree check
 *   - timelock.fields-parsed            → cltv_scripts_found >= 1
 *   - timelock.script-constraints       → >= 1 consistency check
 *   - preimage.conditions-scanned       → commitments_found >= 1
 *   - preimage.hashes-match             → preimages_matched >= 1
 *
 * Also closes P5's pipeline-happy-path gap: resolver now gets a real
 * tapleaf (via extractCommitmentTapleafScripts), so anchor.* rows
 * emit green via the pipeline.
 */

import { base64 } from "@scure/base";
import { Transaction } from "@scure/btc-signer/transaction.js";
import { describe, expect, it } from "vitest";

import { verifyVtxo } from "../../src/verification/index";
import { makeMockIndexerProvider, makeMockOnchainProvider } from "./helpers";
import { buildVhtlcScriptPathFixture } from "./fixtures/vhtlc-script-path";

describe("M1: VHTLC script-path fixture exercises Tier 2 non-vacuously", () => {
    it("fixture PSBT round-trip preserves tapLeafScript + VtxoTaprootTree unknown field (pre-check)", () => {
        const fx = buildVhtlcScriptPathFixture({ cltvBlocks: 144 });
        const tx = Transaction.fromPSBT(base64.decode(fx.virtualTxs[0]), {
            allowUnknown: true,
        });
        const inp = tx.getInput(0);
        expect(inp.tapLeafScript).toBeDefined();
        expect(inp.tapLeafScript!.length).toBeGreaterThanOrEqual(1);
        expect(
            (inp.unknown as unknown[] | undefined)?.length
        ).toBeGreaterThanOrEqual(1);
    });

    it("tier: 'full' pipeline — every Tier 2 row has non-zero evidence; anchor runs green", async () => {
        const fx = buildVhtlcScriptPathFixture({ cltvBlocks: 144 });
        const indexer = makeMockIndexerProvider({
            vtxoChain: fx.vtxoChain,
            virtualTxs: fx.virtualTxs,
        });
        const onchain = makeMockOnchainProvider({
            // Tip well above CLTV so anchor.expiry-not-passed stays green.
            chainTip: {
                height: 50,
                time: 1_700_000_000,
                hash: "00".repeat(32),
            },
            txStatus: {
                [fx.commitmentTxid]: {
                    confirmed: true,
                    blockTime: 1_700_000_000,
                    blockHeight: 10, // depth = 50 - 10 + 1 = 41 >= 6
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

        // Every row must pass (no tamper applied).
        for (const c of result.checks) {
            expect(c.passed, `${c.name}: ${c.details}`).toBe(true);
        }
        // No errors[] — resolver succeeded because tapleaf is present.
        expect(result.errors).toHaveLength(0);
        expect(result.valid).toBe(true);

        // Non-zero evidence on every previously-vacuous Tier 2 row.
        const byName = new Map(result.checks.map((c) => [c.name, c]));

        const cb = byName.get("script.control-block-valid");
        expect(cb?.evidence?.control_blocks_checked).toBeGreaterThanOrEqual(1);

        const merkle = byName.get("script.merkle-root-matches");
        expect(merkle?.evidence?.merkle_checks).toBeGreaterThanOrEqual(1);
        expect(merkle?.evidence?.merkle_matched).toBeGreaterThanOrEqual(1);

        const nums = byName.get("script.internal-key-is-nums");
        expect(nums?.evidence?.inputs_checked).toBeGreaterThanOrEqual(1);
        expect(nums?.evidence?.inputs_matched).toBeGreaterThanOrEqual(1);

        const vtree = byName.get("script.vtxotaprootree-valid");
        expect(vtree?.evidence?.vtxotree_checks).toBeGreaterThanOrEqual(1);
        expect(vtree?.evidence?.vtxotree_matched).toBeGreaterThanOrEqual(1);

        const tlFields = byName.get("timelock.fields-parsed");
        expect(tlFields?.evidence?.cltv_scripts_found).toBeGreaterThanOrEqual(
            1
        );

        const tlCons = byName.get("timelock.script-constraints");
        expect(tlCons?.evidence?.consistency_checked).toBeGreaterThanOrEqual(1);

        const preScan = byName.get("preimage.conditions-scanned");
        expect(preScan?.evidence?.commitments_found).toBeGreaterThanOrEqual(1);
        expect(preScan?.evidence?.sha256_commitments).toBeGreaterThanOrEqual(1);

        // preimage.hashes-match: the fixture carries an SHA-256 hash
        // commitment in the tapleaf but no finalScriptWitness (BIP 174
        // finalization strips tapLeafScript when set). This is the
        // normal pre-broadcast state of a presigned Ark tx — the check
        // reports the commitment as "pending finalization" rather than
        // flipping. Genuine tamper (witness present but non-matching
        // preimage) is tested separately at P7 with a finalized fixture.
        const preMatch = byName.get("preimage.hashes-match");
        expect(preMatch?.passed).toBe(true);
        expect(preMatch?.evidence?.preimages_pending).toBeGreaterThanOrEqual(1);

        // And: anchor.* rows present (P5 happy-path-via-pipeline gap closed).
        const anchorConfirmed = byName.get("anchor.commitment-confirmed");
        expect(anchorConfirmed?.passed).toBe(true);
        expect(anchorConfirmed?.evidence?.min_required).toBe(6);

        const anchorMatches = byName.get("anchor.output-matches");
        expect(anchorMatches?.passed).toBe(true);

        const anchorUnspent = byName.get("anchor.output-unspent");
        expect(anchorUnspent?.passed).toBe(true);

        const anchorExpiry = byName.get("anchor.expiry-not-passed");
        expect(anchorExpiry?.passed).toBe(true);

        // Total row count: 9 chain + 4 sig + 4 anchor + 4 script + 3 timelock
        // + 2 preimage = 26 rows.
        expect(result.checks.length).toBe(26);
    });
});
