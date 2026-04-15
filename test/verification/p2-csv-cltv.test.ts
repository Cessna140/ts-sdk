/**
 * P2 tests — checkpoint CSV coherence (chain.checkpoint-csv-coherent)
 * and CLTV-direct commitment expiry parsing (parseCLTVFromCommitmentScript).
 */

import { describe, expect, it } from "vitest";

import { walkChain } from "../../src/verification/chain-walker";
import {
    CLTV_HEIGHT_THRESHOLD,
    decodeBip68SequenceBlocks,
    parseCLTVFromCommitmentScript,
} from "../../src/verification/types";
import { buildCheckpointChain, makeMockIndexerProvider } from "./helpers";

describe("P2: chain.checkpoint-csv-coherent", () => {
    it("happy path — checkpoint observed CSV matches expected", async () => {
        const fx = buildCheckpointChain({ csvBlocks: 144 });
        const indexer = makeMockIndexerProvider({
            vtxoChain: fx.vtxoChain,
            virtualTxs: fx.virtualTxs,
        });
        const out = await walkChain({
            vtxo: fx.leaf,
            indexerProvider: indexer,
            expectedCsvBlocks: 144,
        });
        const csv = out.checks.find(
            (c) => c.name === "chain.checkpoint-csv-coherent"
        );
        expect(csv?.passed, csv?.details).toBe(true);
        expect(csv?.evidence?.checkpoints_checked).toBe(1);
        expect(csv?.evidence?.csv_expected).toBe(144);
    });

    it("tamper — checkpoint nSequence flipped to 72; only csv-coherent fails", async () => {
        const fx = buildCheckpointChain({
            csvBlocks: 144,
            tamperCheckpointSequence: 72,
        });
        const indexer = makeMockIndexerProvider({
            vtxoChain: fx.vtxoChain,
            virtualTxs: fx.virtualTxs,
        });
        const out = await walkChain({
            vtxo: fx.leaf,
            indexerProvider: indexer,
            expectedCsvBlocks: 144,
        });
        const csv = out.checks.find(
            (c) => c.name === "chain.checkpoint-csv-coherent"
        );
        expect(csv?.passed).toBe(false);
        // All other checks should remain green — tamper localised
        for (const c of out.checks) {
            if (c.name === "chain.checkpoint-csv-coherent") continue;
            expect(c.passed, `${c.name}: ${c.details}`).toBe(true);
        }
    });

    it("no CHECKPOINTs in DAG — check passes trivially with count=0", async () => {
        // buildMockChain produces commitment + tree + leaf, no CHECKPOINT.
        const { buildMockChain } = await import("./helpers");
        const fx = buildMockChain({ depth: 2 });
        const indexer = makeMockIndexerProvider({
            vtxoChain: fx.vtxoChain,
            virtualTxs: fx.virtualTxs,
        });
        const out = await walkChain({
            vtxo: fx.leaf,
            indexerProvider: indexer,
        });
        const csv = out.checks.find(
            (c) => c.name === "chain.checkpoint-csv-coherent"
        );
        expect(csv?.passed).toBe(true);
        expect(csv?.evidence?.checkpoints_checked).toBe(0);
    });
});

describe("P2: decodeBip68SequenceBlocks", () => {
    it("disable bit set → null", () => {
        expect(decodeBip68SequenceBlocks(0x80000001)).toBeNull();
    });
    it("type bit (time) set → null", () => {
        expect(decodeBip68SequenceBlocks(0x00400042)).toBeNull();
    });
    it("block count — low 16 bits", () => {
        expect(decodeBip68SequenceBlocks(144)).toBe(144);
        expect(decodeBip68SequenceBlocks(0xffff)).toBe(0xffff);
    });
});

describe("P2: parseCLTVFromCommitmentScript", () => {
    it("parses small CLTV push: OP_1 OP_CLTV (height 1)", () => {
        const script = new Uint8Array([0x51, 0xb1]); // OP_1, OP_CLTV
        expect(parseCLTVFromCommitmentScript(script)).toBe(1);
    });

    it("parses direct push: <2-byte 144> OP_CLTV (height 144)", () => {
        // 144 = 0x90; as CScriptNum minimal, needs 2 bytes because top bit set:
        // [0x90, 0x00] encodes positive 144 (sign-bit disambiguation).
        const script = new Uint8Array([0x02, 0x90, 0x00, 0xb1]);
        expect(parseCLTVFromCommitmentScript(script)).toBe(144);
    });

    it("parses push with OP_DROP / OP_EQUAL follow-up opcodes before CLTV", () => {
        // <push 100> OP_CLTV OP_DROP...
        // 100 = 0x64, single byte CScriptNum (no sign bit).
        const script = new Uint8Array([0x01, 0x64, 0xb1, 0x75]);
        expect(parseCLTVFromCommitmentScript(script)).toBe(100);
    });

    it("rejects timestamp-shaped values (>= 500_000_000)", () => {
        // 500_000_000 = 0x1DCD6500; 4 bytes little-endian: 00 65 CD 1D
        const script = new Uint8Array([0x04, 0x00, 0x65, 0xcd, 0x1d, 0xb1]);
        expect(() => parseCLTVFromCommitmentScript(script)).toThrow(
            /timestamp/
        );
    });

    it("rejects scripts without OP_CLTV", () => {
        const script = new Uint8Array([0x51, 0x52, 0x53]); // OP_1 OP_2 OP_3
        expect(() => parseCLTVFromCommitmentScript(script)).toThrow(
            /no OP_CHECKLOCKTIMEVERIFY/
        );
    });

    it("rejects OP_CLTV with no preceding push", () => {
        const script = new Uint8Array([0xb1]);
        expect(() => parseCLTVFromCommitmentScript(script)).toThrow(
            /no preceding push/
        );
    });

    it("CLTV_HEIGHT_THRESHOLD is 500_000_000 per BIP 65", () => {
        expect(CLTV_HEIGHT_THRESHOLD).toBe(500_000_000);
    });

    it("rejects negative CScriptNum via OP_1NEGATE (BIP 65 forbids negatives)", () => {
        // OP_1NEGATE (0x4f), OP_CLTV (0xb1)
        const script = new Uint8Array([0x4f, 0xb1]);
        expect(() => parseCLTVFromCommitmentScript(script)).toThrow(
            /negative value/
        );
    });

    it("rejects negative CScriptNum via direct-push with sign bit", () => {
        // [len=1, 0x81] — sign bit set, value = -1
        const script = new Uint8Array([0x01, 0x81, 0xb1]);
        expect(() => parseCLTVFromCommitmentScript(script)).toThrow(
            /negative value/
        );
    });
});
