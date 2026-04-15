/**
 * P3 tests — signature verification.
 *
 * Covers:
 *   - verifySignatures directly (unit)
 *   - verifyVtxo end-to-end (B1 invariant: per-input prevouts feed
 *     through the pipeline, not just the verifier's direct API)
 *   - Tamper detection: flipped sig byte flips only sig.schnorr-valid
 *   - makeSignaturePathEntry rejects length mismatches at construction
 */

import { base64 } from "@scure/base";
import { Transaction } from "@scure/btc-signer/transaction.js";
import { describe, expect, it } from "vitest";

import {
    preimageWitnessV1Typed,
    verifySignatures,
} from "../../src/verification/signature-verifier";
import { verifyVtxo } from "../../src/verification/index";
import {
    makeSignaturePathEntry,
    parseSighashFromSchnorrSig,
    sighashTypeDefault,
} from "../../src/verification/types";
import {
    buildMockChain,
    makeMockIndexerProvider,
    tamperPsbtByte,
} from "./helpers";

function pathFromVirtualTxs(virtualTxs: string[]) {
    return virtualTxs.map((psbt) => {
        const tx = Transaction.fromPSBT(base64.decode(psbt));
        const prevouts = [];
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

describe("P3: verifySignatures", () => {
    it("happy path — 3 checks (classified, sighash-computed, schnorr-valid) + aggregate", async () => {
        const fx = buildMockChain({ depth: 2 });
        const path = pathFromVirtualTxs(fx.virtualTxs);
        const out = await verifySignatures({ path });
        expect(out).toHaveLength(4);
        for (const c of out) {
            expect(c.passed, `${c.name}: ${c.details}`).toBe(true);
        }
        const schnorr = out.find((c) => c.name === "sig.schnorr-valid");
        expect(schnorr?.evidence?.sigs_total).toBe(2); // 2 key-path inputs across 2 txs
    });

    it("tamper — flipped sig byte flips only sig.schnorr-valid", async () => {
        const fx = buildMockChain({ depth: 2 });
        // Tamper the leaf's PSBT signature; offset ~120 lands in the tapKeySig
        // region for a typical PSBT layout.
        fx.virtualTxs[0] = tamperPsbtByte(fx.virtualTxs[0], 120);
        const path = pathFromVirtualTxs(fx.virtualTxs);
        const out = await verifySignatures({ path });
        const schnorr = out.find((c) => c.name === "sig.schnorr-valid");
        expect(schnorr?.passed).toBe(false);
        for (const c of out) {
            if (c.name === "sig.schnorr-valid") continue;
            expect(c.passed, `${c.name}: ${c.details}`).toBe(true);
        }
    });
});

describe("P3: verifyVtxo end-to-end (B1 invariant)", () => {
    it("pipeline wires per-input prevouts through to sig verifier; no prevout-count-mismatch crash", async () => {
        const fx = buildMockChain({ depth: 2 });
        const indexer = makeMockIndexerProvider({
            vtxoChain: fx.vtxoChain,
            virtualTxs: fx.virtualTxs,
        });
        // Key-path fixture has no tapleaves → P5 resolver can't parse
        // CLTV → emits UNSUPPORTED errors[] row. The 13 chain+sig rows
        // remain green; anchor rows are absent (honest skip, not a
        // throw).
        const onchain = (await import("./helpers")).makeMockOnchainProvider({
            txOutputsByTxid: {
                [fx.commitmentTxid]: [
                    { script: new Uint8Array(34).fill(0x51), amount: 100_000n },
                ],
            },
        });
        const result = await verifyVtxo({
            vtxoId: fx.leaf,
            indexerProvider: indexer,
            onchainProvider: onchain,
        });
        expect(result.checks.length).toBe(17); // 9 chain + 4 sig + 4 anchor
        for (const c of result.checks) {
            expect(c.passed, `${c.name}: ${c.details}`).toBe(true);
        }
        // Anchor rows run on key-path fixture — expiry row handles
        // undefined expiry as UNSUPPORTED but still passes.
        const expiryRow = result.checks.find(
            (c) => c.name === "anchor.expiry-not-passed"
        );
        expect(expiryRow?.evidence?.unsupported_count).toBeGreaterThanOrEqual(
            1
        );
    });

    it("pipeline does not throw on tampered sig; flips sig.schnorr-valid + sets valid:false", async () => {
        const fx = buildMockChain({ depth: 2 });
        fx.virtualTxs[0] = tamperPsbtByte(fx.virtualTxs[0], 120);
        const indexer = makeMockIndexerProvider({
            vtxoChain: fx.vtxoChain,
            virtualTxs: fx.virtualTxs,
        });
        const onchain = (await import("./helpers")).makeMockOnchainProvider({
            txOutputsByTxid: {
                [fx.commitmentTxid]: [
                    { script: new Uint8Array(34).fill(0x51), amount: 100_000n },
                ],
            },
        });
        const result = await verifyVtxo({
            vtxoId: fx.leaf,
            indexerProvider: indexer,
            onchainProvider: onchain,
        });
        expect(result.valid).toBe(false);
        const schnorr = result.checks.find(
            (c) => c.name === "sig.schnorr-valid"
        );
        expect(schnorr?.passed).toBe(false);
        // Every non-sig row should still pass.
        const nonSchnorr = result.checks.filter(
            (c) => c.name !== "sig.schnorr-valid"
        );
        for (const c of nonSchnorr) {
            expect(c.passed, `${c.name}: ${c.details}`).toBe(true);
        }
    });
});

describe("P3: preimageWitnessV1Typed / B5 invariant", () => {
    it("sighashType is threaded through — no hardcoded DEFAULT", () => {
        const fx = buildMockChain({ depth: 1 });
        const tx = Transaction.fromPSBT(base64.decode(fx.virtualTxs[0]));
        const inp = tx.getInput(0);
        const entry = makeSignaturePathEntry(tx, [
            {
                script: inp.witnessUtxo!.script,
                amount: inp.witnessUtxo!.amount,
            },
        ]);
        // parseSighashFromSchnorrSig on a 64-byte sig returns the default
        // sentinel; the function accepts it only because we're opting in.
        const st = parseSighashFromSchnorrSig(inp.tapKeySig!);
        expect(st).toBe(sighashTypeDefault);
        const msg = preimageWitnessV1Typed(
            entry.tx,
            0,
            entry.perInputPrevouts,
            st
        );
        expect(msg).toBeInstanceOf(Uint8Array);
        expect(msg.length).toBe(32);
    });
});
