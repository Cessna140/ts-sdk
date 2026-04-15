/**
 * P5 tests — anchor verifier + commitment resolver.
 *
 * Covers:
 *   - verifyAnchor: 4 anchor.* checks on hand-built ResolvedCommitmentInfo[]
 *   - resolveCommitments: B9 CLTV parse + B7 error-variant handling
 *   - extractCommitmentTapleafScripts: DAG iterator builds the map
 *   - Pipeline: end-to-end with mock onchain provider (expected errors
 *     on key-path-only fixture because no tapleaf to parse CLTV from)
 */

import { hex } from "@scure/base";
import { describe, expect, it } from "vitest";

import { verifyVtxo } from "../../src/verification/index";
import {
    resolveCommitments,
    verifyAnchor,
    anchorVoutInRange,
    DEFAULT_MIN_CONFIRMATIONS,
} from "../../src/verification/anchor-verifier";
import {
    txidFromString,
    type BlockHeight,
    type ResolvedCommitmentInfo,
    type UnresolvedCommitmentInfo,
} from "../../src/verification/types";
import {
    buildMockChain,
    fakeCommitmentTxid,
    makeMockIndexerProvider,
    makeMockOnchainProvider,
} from "./helpers";

function p2tr32(): Uint8Array {
    const out = new Uint8Array(34);
    out[0] = 0x51;
    out[1] = 0x20;
    for (let i = 2; i < 34; i++) out[i] = i;
    return out;
}

// A tapleaf script containing <144> OP_CHECKLOCKTIMEVERIFY.
// 144 = 0x90; minimal CScriptNum is [0x90, 0x00]; push opcode 0x02.
const CLTV_144_TAPLEAF = new Uint8Array([0x02, 0x90, 0x00, 0xb1]);

function resolvedCommitment(
    txid: string,
    vout: number,
    amount: bigint,
    expiry: number
): ResolvedCommitmentInfo {
    return {
        txid: txidFromString(txid),
        vout,
        batchScript: p2tr32(),
        batchAmount: amount,
        batchExpiryHeight: expiry as BlockHeight,
    };
}

describe("P5: verifyAnchor — 4 anchor.* checks", () => {
    it("happy path — all 4 green on confirmed/unspent/pre-expiry", async () => {
        const txid = fakeCommitmentTxid(0xc0);
        const commitments = [resolvedCommitment(txid, 0, 100_000n, 500)];
        const onchain = makeMockOnchainProvider({
            chainTip: { height: 200, time: 0, hash: "00".repeat(32) },
            txStatus: {
                [txid]: {
                    confirmed: true,
                    blockTime: 0,
                    blockHeight: 100,
                },
            },
            outspendsByTxid: {
                [txid]: [{ spent: false, txid: "" }],
            },
        });
        const checks = await verifyAnchor({
            commitments,
            onchainProvider: onchain,
        });
        expect(checks).toHaveLength(4);
        for (const c of checks) {
            expect(c.passed, `${c.name}: ${c.details}`).toBe(true);
        }
    });

    it("anchor.commitment-confirmed flips when depth < minConfirmations", async () => {
        const txid = fakeCommitmentTxid(0xc1);
        const commitments = [resolvedCommitment(txid, 0, 100_000n, 500)];
        // tip=101, blockHeight=100 → depth=2 → below DEFAULT_MIN_CONFIRMATIONS=6
        const onchain = makeMockOnchainProvider({
            chainTip: { height: 101, time: 0, hash: "00".repeat(32) },
            txStatus: {
                [txid]: { confirmed: true, blockTime: 0, blockHeight: 100 },
            },
        });
        const checks = await verifyAnchor({
            commitments,
            onchainProvider: onchain,
        });
        const confirmed = checks.find(
            (c) => c.name === "anchor.commitment-confirmed"
        );
        expect(confirmed?.passed).toBe(false);
        expect(DEFAULT_MIN_CONFIRMATIONS).toBe(6);
    });

    it("anchor.output-unspent flips when outspends[vout].spent is true", async () => {
        const txid = fakeCommitmentTxid(0xc2);
        const commitments = [resolvedCommitment(txid, 0, 100_000n, 500)];
        const onchain = makeMockOnchainProvider({
            outspendsByTxid: {
                [txid]: [{ spent: true, txid: "de".repeat(32) }],
            },
        });
        const checks = await verifyAnchor({
            commitments,
            onchainProvider: onchain,
        });
        const unspent = checks.find((c) => c.name === "anchor.output-unspent");
        expect(unspent?.passed).toBe(false);
    });

    it("anchor.expiry-not-passed flips when tip >= batchExpiryHeight", async () => {
        const txid = fakeCommitmentTxid(0xc3);
        const commitments = [resolvedCommitment(txid, 0, 100_000n, 100)];
        // expiry=100, tip=200 → expired
        const onchain = makeMockOnchainProvider({
            chainTip: { height: 200, time: 0, hash: "00".repeat(32) },
        });
        const checks = await verifyAnchor({
            commitments,
            onchainProvider: onchain,
        });
        const expiry = checks.find(
            (c) => c.name === "anchor.expiry-not-passed"
        );
        expect(expiry?.passed).toBe(false);
    });
});

describe("P5: resolveCommitments (B7 + B9 invariants)", () => {
    it("happy path — resolver fills ResolvedCommitmentInfo from onchain + tapleaf", async () => {
        const txid = fakeCommitmentTxid(0xd0);
        const onchain = makeMockOnchainProvider({
            txOutputsByTxid: {
                [txid]: [
                    { script: p2tr32(), amount: 50_000n },
                    { script: p2tr32(), amount: 50_000n },
                ],
            },
        });
        const unresolved: UnresolvedCommitmentInfo[] = [
            { txid: txidFromString(txid), claimedVouts: [0, 1] },
        ];
        const tapleafMap = new Map([[txidFromString(txid), CLTV_144_TAPLEAF]]);
        const res = await resolveCommitments(
            unresolved,
            onchain,
            tapleafMap,
            new Map()
        );
        expect(res.ok).toBe(true);
        if (res.ok) {
            expect(res.value).toHaveLength(2); // one per claimed vout (bug #8 fix)
            for (const r of res.value) {
                expect(r.batchExpiryHeight).toBe(144);
                expect(r.batchAmount).toBe(50_000n);
            }
        }
    });

    it("missing expiry source resolves with undefined batchExpiryHeight (§3.1.3 core rows decoupled from expiry)", async () => {
        const txid = fakeCommitmentTxid(0xd1);
        const onchain = makeMockOnchainProvider({
            txOutputsByTxid: {
                [txid]: [{ script: p2tr32(), amount: 50_000n }],
            },
        });
        const unresolved: UnresolvedCommitmentInfo[] = [
            { txid: txidFromString(txid), claimedVouts: [0] },
        ];
        const emptyMap = new Map();
        const res = await resolveCommitments(
            unresolved,
            onchain,
            emptyMap,
            new Map()
        );
        // Resolver succeeds — core §3.1.3 checks (confirmed/output-
        // matches/unspent) don't need expiry. Row 4 handles undefined
        // expiry via UNSUPPORTED.
        expect(res.ok).toBe(true);
        if (res.ok) {
            expect(res.value).toHaveLength(1);
            expect(res.value[0].batchExpiryHeight).toBeUndefined();
            expect(res.value[0].batchScript).toBeDefined();
            expect(res.value[0].batchAmount).toBe(50_000n);
        }
    });

    it("B7 — out-of-range vout returns error variant", async () => {
        const txid = fakeCommitmentTxid(0xd2);
        const onchain = makeMockOnchainProvider({
            txOutputsByTxid: {
                [txid]: [{ script: p2tr32(), amount: 50_000n }],
            },
        });
        const unresolved: UnresolvedCommitmentInfo[] = [
            { txid: txidFromString(txid), claimedVouts: [5] }, // only 1 output
        ];
        const tapleafMap = new Map([[txidFromString(txid), CLTV_144_TAPLEAF]]);
        const res = await resolveCommitments(
            unresolved,
            onchain,
            tapleafMap,
            new Map()
        );
        expect(res.ok).toBe(false);
        if (!res.ok) expect(res.error).toMatch(/vout 5 out of range/);
    });

    it("B9 — timestamp-shaped CLTV value leaves expiry undefined (no silent coercion)", async () => {
        const txid = fakeCommitmentTxid(0xd3);
        const onchain = makeMockOnchainProvider({
            txOutputsByTxid: {
                [txid]: [{ script: p2tr32(), amount: 50_000n }],
            },
        });
        // 500_000_000 is a timestamp per BIP 65; parseCLTV rejects it.
        const timestampTapleaf = new Uint8Array([
            0x04, 0x00, 0x65, 0xcd, 0x1d, 0xb1,
        ]);
        const tapleafMap = new Map([[txidFromString(txid), timestampTapleaf]]);
        const unresolved: UnresolvedCommitmentInfo[] = [
            { txid: txidFromString(txid), claimedVouts: [0] },
        ];
        const res = await resolveCommitments(
            unresolved,
            onchain,
            tapleafMap,
            new Map()
        );
        // Resolver still succeeds (on-chain outputs fetched); expiry
        // left undefined — no silent coercion from timestamp.
        expect(res.ok).toBe(true);
        if (res.ok) {
            expect(res.value[0].batchExpiryHeight).toBeUndefined();
        }
    });
});

describe("P5: anchorVoutInRange (B6 invariant)", () => {
    it("returns CheckResult; does not throw on out-of-range", () => {
        const out = anchorVoutInRange(99, 2);
        expect(out.name).toBe("anchor.vout-in-range");
        expect(out.passed).toBe(false);
        expect(out.evidence?.vout).toBe(99);
        expect(out.evidence?.outputs_length).toBe(2);
    });
    it("passes when in range", () => {
        expect(anchorVoutInRange(0, 2).passed).toBe(true);
        expect(anchorVoutInRange(1, 2).passed).toBe(true);
    });
});

describe("P5: pipeline end-to-end", () => {
    it("key-path-only fixture: anchor stage runs all 4 rows green (expiry UNSUPPORTED for commitments without block-based source)", async () => {
        const fx = buildMockChain({ depth: 2 });
        const indexer = makeMockIndexerProvider({
            vtxoChain: fx.vtxoChain,
            virtualTxs: fx.virtualTxs,
        });
        const onchain = makeMockOnchainProvider({
            txOutputsByTxid: {
                [fx.commitmentTxid]: [{ script: p2tr32(), amount: 100_000n }],
            },
        });
        const result = await verifyVtxo({
            vtxoId: fx.leaf,
            indexerProvider: indexer,
            onchainProvider: onchain,
        });
        // 9 chain + 4 sig + 4 anchor = 17 rows; all green (§3.1.3
        // core rows decoupled from expiry source).
        expect(result.checks.length).toBe(17);
        for (const c of result.checks) {
            expect(c.passed, `${c.name}: ${c.details}`).toBe(true);
        }
        // Expiry row passed with UNSUPPORTED note (no tapleaf source).
        const expiryRow = result.checks.find(
            (c) => c.name === "anchor.expiry-not-passed"
        );
        expect(expiryRow?.passed).toBe(true);
        expect(expiryRow?.evidence?.unsupported_count).toBeGreaterThanOrEqual(
            1
        );
        expect(result.errors).toHaveLength(0);
        expect(result.valid).toBe(true);
    });
});
