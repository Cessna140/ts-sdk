/**
 * Test helpers for the verification module. Provides:
 *   - `buildKeyPathTx` — constructs a valid BIP 340 Schnorr-signed PSBT
 *   - `buildMockChain` — a linear single-root fixture
 *   - `buildMockMultiRootChain` — a 2-root fixture (multi-root DAG)
 *   - `buildDiamondChain` — diamond topology (one parent, two children)
 *   - `buildDeepChain` — N-deep single-root chain (for DoS bound tests)
 *   - mock indexer provider
 *
 * Hand-built synthesised fixtures (cycle / orphan / self-loop / too-large)
 * bypass the PSBT path entirely — those failure modes are structural and
 * raise in `buildDag` before any tx parsing runs.
 */

import { base64, hex } from "@scure/base";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { SigHash, Transaction } from "@scure/btc-signer/transaction.js";
import { vi } from "vitest";

import type {
    ChainTx,
    IndexerProvider,
    VtxoChain,
} from "../../src/providers/indexer";
import { ChainTxType } from "../../src/providers/indexer";
import type { Outpoint } from "../../src/wallet";

/** A key-path Taproot output: OP_1 + 32-byte x-only pubkey. */
export function p2trScript(xOnly: Uint8Array): Uint8Array {
    if (xOnly.length !== 32) throw new Error("p2trScript needs 32 bytes");
    const out = new Uint8Array(34);
    out[0] = 0x51;
    out[1] = 0x20;
    out.set(xOnly, 2);
    return out;
}

export function xOnlyPubkey(privkey: Uint8Array): Uint8Array {
    const pub = secp256k1.getPublicKey(privkey, true);
    return pub.subarray(1);
}

export const TEST_KEYS = {
    leafSigner: hex.decode(
        "1111111111111111111111111111111111111111111111111111111111111111"
    ),
    branchSigner: hex.decode(
        "2222222222222222222222222222222222222222222222222222222222222222"
    ),
};

export interface BuildTxInput {
    parentTxid: string;
    parentVout: number;
    parentScript: Uint8Array;
    parentAmount: bigint;
    signingKey: Uint8Array;
    outputs: Array<{ script: Uint8Array; amount: bigint }>;
    additionalInputs?: Array<{
        parentTxid: string;
        parentVout: number;
        parentScript: Uint8Array;
        parentAmount: bigint;
    }>;
}

export interface BuiltTx {
    psbtBase64: string;
    tx: Transaction;
    txid: string;
}

export function buildKeyPathTx(opts: BuildTxInput): BuiltTx {
    const tx = new Transaction({ version: 2, allowUnknownOutputs: true });
    tx.addInput({
        txid: opts.parentTxid,
        index: opts.parentVout,
        witnessUtxo: { script: opts.parentScript, amount: opts.parentAmount },
        sequence: 0xfffffffd,
    });
    for (const extra of opts.additionalInputs ?? []) {
        tx.addInput({
            txid: extra.parentTxid,
            index: extra.parentVout,
            witnessUtxo: {
                script: extra.parentScript,
                amount: extra.parentAmount,
            },
            sequence: 0xfffffffd,
        });
    }
    for (const out of opts.outputs) {
        tx.addOutput({ script: out.script, amount: out.amount });
    }
    // Sign input 0 only (single-sig tests).
    const sighash = tx.preimageWitnessV1(
        0,
        [
            opts.parentScript,
            ...(opts.additionalInputs ?? []).map((x) => x.parentScript),
        ],
        SigHash.DEFAULT,
        [
            opts.parentAmount,
            ...(opts.additionalInputs ?? []).map((x) => x.parentAmount),
        ]
    );
    const sig = schnorr.sign(sighash, opts.signingKey);
    tx.updateInput(0, { tapKeySig: sig });
    const bytes = tx.toPSBT();
    return {
        psbtBase64: base64.encode(bytes),
        tx: Transaction.fromPSBT(bytes),
        txid: tx.id,
    };
}

export interface MockChainFixture {
    leaf: Outpoint;
    vtxoChain: VtxoChain;
    virtualTxs: string[];
    commitmentTxid: string;
}

export interface MockChainOptions {
    depth?: number;
    batchAmountSats?: bigint;
    feePerHopSats?: bigint;
    commitmentTxid?: string;
}

/** Fabricate a 64-char lowercase-hex txid from a numeric seed. */
export function fakeCommitmentTxid(seed: number): string {
    const n = seed.toString(16).padStart(2, "0");
    return n + "aa".repeat(31);
}

/**
 * Single-root linear DAG. commitment ← branch ← leaf (depth=2 default).
 */
export function buildMockChain(
    options: MockChainOptions = {}
): MockChainFixture {
    const depth = options.depth ?? 2;
    const batchAmount = options.batchAmountSats ?? 100_000n;
    const feePerHop = options.feePerHopSats ?? 500n;
    const commitmentTxid = options.commitmentTxid ?? fakeCommitmentTxid(0xc0);

    const branchPub = xOnlyPubkey(TEST_KEYS.branchSigner);
    const batchScript = p2trScript(branchPub);

    const built: BuiltTx[] = [];
    let parentTxid = commitmentTxid;
    let parentScript = batchScript;
    let parentAmount = batchAmount;
    for (let level = 0; level < depth; level++) {
        const isLeaf = level === depth - 1;
        const childScript = p2trScript(
            isLeaf
                ? xOnlyPubkey(TEST_KEYS.leafSigner)
                : xOnlyPubkey(TEST_KEYS.branchSigner)
        );
        const b = buildKeyPathTx({
            parentTxid,
            parentVout: 0,
            parentScript,
            parentAmount,
            signingKey: TEST_KEYS.branchSigner,
            outputs: [
                { script: childScript, amount: parentAmount - feePerHop },
            ],
        });
        built.push(b);
        parentTxid = b.txid;
        parentScript = childScript;
        parentAmount -= feePerHop;
    }
    built.reverse(); // leaf first

    const expiresAt = new Date(Date.now() + 604800000).toISOString();
    const chain: ChainTx[] = [];
    for (let i = 0; i < built.length; i++) {
        const isTop = i === built.length - 1;
        chain.push({
            txid: built[i].txid,
            expiresAt,
            type: ChainTxType.TREE,
            spends: isTop ? [commitmentTxid] : [built[i + 1].txid],
        });
    }
    chain.push({
        txid: commitmentTxid,
        expiresAt,
        type: ChainTxType.COMMITMENT,
        spends: [],
    });

    return {
        leaf: { txid: built[0].txid, vout: 0 },
        vtxoChain: { chain },
        virtualTxs: built.map((b) => b.psbtBase64),
        commitmentTxid,
    };
}

/**
 * Build a key-path tx whose input 0 has a specific nSequence value.
 * Used to synthesise checkpoint fixtures for the CSV-coherence check.
 */
export function buildKeyPathTxWithSequence(
    opts: BuildTxInput & { sequence: number }
): BuiltTx {
    const tx = new Transaction({ version: 2, allowUnknownOutputs: true });
    tx.addInput({
        txid: opts.parentTxid,
        index: opts.parentVout,
        witnessUtxo: { script: opts.parentScript, amount: opts.parentAmount },
        sequence: opts.sequence,
    });
    for (const out of opts.outputs) {
        tx.addOutput({ script: out.script, amount: out.amount });
    }
    const sighash = tx.preimageWitnessV1(
        0,
        [opts.parentScript],
        SigHash.DEFAULT,
        [opts.parentAmount]
    );
    const sig = schnorr.sign(sighash, opts.signingKey);
    tx.updateInput(0, { tapKeySig: sig });
    const bytes = tx.toPSBT();
    return {
        psbtBase64: base64.encode(bytes),
        tx: Transaction.fromPSBT(bytes),
        txid: tx.id,
    };
}

/**
 * Single-root chain with a CHECKPOINT node between the leaf and
 * commitment. Every CHECKPOINT carries nSequence = `csvBlocks` (BIP 68
 * relative-lock block-count encoding).
 *
 * Layout: commitment ← checkpoint[seq=csvBlocks] ← leaf
 */
export function buildCheckpointChain(opts: {
    csvBlocks: number;
    /** If set, override only the checkpoint's sequence to this value. */
    tamperCheckpointSequence?: number;
}): MockChainFixture {
    const branchPub = xOnlyPubkey(TEST_KEYS.branchSigner);
    const batchScript = p2trScript(branchPub);
    const commitmentTxid = fakeCommitmentTxid(0xc4);
    const batchAmount = 100_000n;
    const feePerHop = 500n;

    const checkpointScript = p2trScript(branchPub);
    const checkpoint = buildKeyPathTxWithSequence({
        parentTxid: commitmentTxid,
        parentVout: 0,
        parentScript: batchScript,
        parentAmount: batchAmount,
        signingKey: TEST_KEYS.branchSigner,
        sequence:
            opts.tamperCheckpointSequence !== undefined
                ? opts.tamperCheckpointSequence
                : opts.csvBlocks,
        outputs: [
            {
                script: checkpointScript,
                amount: batchAmount - feePerHop,
            },
        ],
    });
    const leafScript = p2trScript(xOnlyPubkey(TEST_KEYS.leafSigner));
    const leaf = buildKeyPathTx({
        parentTxid: checkpoint.txid,
        parentVout: 0,
        parentScript: checkpointScript,
        parentAmount: batchAmount - feePerHop,
        signingKey: TEST_KEYS.branchSigner,
        outputs: [
            {
                script: leafScript,
                amount: batchAmount - feePerHop * 2n,
            },
        ],
    });
    const expiresAt = new Date(Date.now() + 604800000).toISOString();
    const chain: ChainTx[] = [
        {
            txid: leaf.txid,
            expiresAt,
            type: ChainTxType.TREE,
            spends: [checkpoint.txid],
        },
        {
            txid: checkpoint.txid,
            expiresAt,
            type: ChainTxType.CHECKPOINT,
            spends: [commitmentTxid],
        },
        {
            txid: commitmentTxid,
            expiresAt,
            type: ChainTxType.COMMITMENT,
            spends: [],
        },
    ];
    return {
        leaf: { txid: leaf.txid, vout: 0 },
        vtxoChain: { chain },
        virtualTxs: [leaf.psbtBase64, checkpoint.psbtBase64],
        commitmentTxid,
    };
}

/**
 * Multi-root DAG: leaf has 2 inputs, each into a distinct commitment.
 * Mimics the Arkoor multi-root shape (bug B3/B4 target).
 */
export function buildMockMultiRootChain(): MockChainFixture {
    const branchPub = xOnlyPubkey(TEST_KEYS.branchSigner);
    const batchScript = p2trScript(branchPub);
    const c1 = fakeCommitmentTxid(0xa1);
    const c2 = fakeCommitmentTxid(0xa2);

    // Leaf has 2 inputs: one from c1, one from c2.
    const leaf = buildKeyPathTx({
        parentTxid: c1,
        parentVout: 0,
        parentScript: batchScript,
        parentAmount: 50_000n,
        signingKey: TEST_KEYS.branchSigner,
        additionalInputs: [
            {
                parentTxid: c2,
                parentVout: 0,
                parentScript: batchScript,
                parentAmount: 50_000n,
            },
        ],
        outputs: [
            {
                script: p2trScript(xOnlyPubkey(TEST_KEYS.leafSigner)),
                amount: 99_000n,
            },
        ],
    });

    const expiresAt = new Date(Date.now() + 604800000).toISOString();
    const chain: ChainTx[] = [
        {
            txid: leaf.txid,
            expiresAt,
            type: ChainTxType.ARK,
            spends: [c1, c2],
        },
        {
            txid: c1,
            expiresAt,
            type: ChainTxType.COMMITMENT,
            spends: [],
        },
        {
            txid: c2,
            expiresAt,
            type: ChainTxType.COMMITMENT,
            spends: [],
        },
    ];

    return {
        leaf: { txid: leaf.txid, vout: 0 },
        vtxoChain: { chain },
        virtualTxs: [leaf.psbtBase64],
        commitmentTxid: c1,
    };
}

/**
 * Synthesise a bogus ChainTx[] for structural-failure tests. These
 * fixtures never produce PSBTs — `buildDag` fails before fetch.
 */
export function buildCycleChain(): { leaf: Outpoint; vtxoChain: VtxoChain } {
    // Leaf a has two parents: b (which cycles back to a) and commitment c.
    // The commitment gives the DAG a root so `no-commitment-root` doesn't
    // fire first; Kahn's topo sort then catches the a↔b cycle.
    const a = "aa".repeat(32);
    const b = "bb".repeat(32);
    const c = "cc".repeat(32);
    const chain: ChainTx[] = [
        { txid: a, expiresAt: "", type: ChainTxType.TREE, spends: [b, c] },
        { txid: b, expiresAt: "", type: ChainTxType.TREE, spends: [a] },
        { txid: c, expiresAt: "", type: ChainTxType.COMMITMENT, spends: [] },
    ];
    return { leaf: { txid: a, vout: 0 }, vtxoChain: { chain } };
}

export function buildSelfLoopChain(): {
    leaf: Outpoint;
    vtxoChain: VtxoChain;
} {
    const a = "ab".repeat(32);
    const chain: ChainTx[] = [
        { txid: a, expiresAt: "", type: ChainTxType.TREE, spends: [a] },
    ];
    return { leaf: { txid: a, vout: 0 }, vtxoChain: { chain } };
}

export function buildOrphanChain(): { leaf: Outpoint; vtxoChain: VtxoChain } {
    const a = "ac".repeat(32);
    const missing = "de".repeat(32);
    const chain: ChainTx[] = [
        { txid: a, expiresAt: "", type: ChainTxType.TREE, spends: [missing] },
    ];
    return { leaf: { txid: a, vout: 0 }, vtxoChain: { chain } };
}

export function buildTooLargeChain(n: number): {
    leaf: Outpoint;
    vtxoChain: VtxoChain;
} {
    const chain: ChainTx[] = [];
    for (let i = 0; i < n; i++) {
        const txid = i.toString(16).padStart(64, "0");
        chain.push({
            txid,
            expiresAt: "",
            type: ChainTxType.TREE,
            spends: [],
        });
    }
    return { leaf: { txid: chain[0].txid, vout: 0 }, vtxoChain: { chain } };
}

export interface MockIndexerOptions {
    vtxoChain?: VtxoChain;
    virtualTxs?: string[];
    vtxoChainError?: Error;
    virtualTxsError?: Error;
}

export function makeMockIndexerProvider(
    opts: MockIndexerOptions = {}
): IndexerProvider {
    const stub = (msg: string) =>
        vi.fn(async () => {
            throw new Error(`${msg} not mocked`);
        });
    return {
        getVtxoChain: vi.fn(async () => {
            if (opts.vtxoChainError) throw opts.vtxoChainError;
            if (!opts.vtxoChain)
                throw new Error("Mock indexer: no vtxoChain configured");
            return opts.vtxoChain;
        }),
        getVirtualTxs: vi.fn(async () => {
            if (opts.virtualTxsError) throw opts.virtualTxsError;
            return { txs: opts.virtualTxs ?? [] };
        }),
        getVtxoTree: vi.fn(async () => ({ vtxoTree: [] })),
        getVtxoTreeLeaves: vi.fn(async () => ({ leaves: [] })),
        getBatchSweepTransactions: vi.fn(async () => ({ sweptBy: [] })),
        getCommitmentTx: stub("getCommitmentTx"),
        getCommitmentTxConnectors: vi.fn(async () => ({ connectors: [] })),
        getCommitmentTxForfeitTxs: vi.fn(async () => ({ txids: [] })),
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        getSubscription: vi.fn(() => {
            throw new Error("getSubscription not mocked");
        }) as any,
        getVtxos: vi.fn(async () => ({ vtxos: [] })),
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        getAssetDetails: stub("getAssetDetails") as any,
        subscribeForScripts: vi.fn(async () => ""),
        unsubscribeForScripts: vi.fn(async () => {}),
    };
}
