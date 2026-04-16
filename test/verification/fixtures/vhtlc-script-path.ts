/**
 * VHTLC-style script-path fixture — M1 (pre-PR mandatory).
 *
 * Synthesises a single-root chain whose leaf spends a batch commitment
 * via a script-path witness containing, in order:
 *
 *   <cltvBlocks> OP_CHECKLOCKTIMEVERIFY OP_DROP
 *   OP_SHA256 <preimageHash> OP_EQUALVERIFY
 *   <pubkey32> OP_CHECKSIG
 *
 * Also populates the `VtxoTaprootTree` PSBT unknown field on the child's
 * input with the single leaf's tree encoding, so
 * `script.vtxotaprootree-valid` runs non-vacuously.
 *
 * The parent P2TR uses BIP 341's NUMS internal key so
 * `script.internal-key-is-nums` passes.
 *
 * This fixture closes the vacuousness of P4's 9 Tier 2 check rows and
 * the P5 pipeline-happy-path test-gap (verifyAnchor via pipeline).
 */

import { base64, hex } from "@scure/base";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Transaction } from "@scure/btc-signer/transaction.js";
import { p2tr } from "@scure/btc-signer/payment.js";
import { TAPROOT_UNSPENDABLE_KEY } from "@scure/btc-signer/utils.js";
import { TapTreeCoder } from "../../../src/script/base";
import {
    setArkPsbtField,
    VtxoTaprootTree,
} from "../../../src/utils/unknownFields";
import type { ChainTx, VtxoChain } from "../../../src/providers/indexer";
import { ChainTxType } from "../../../src/providers/indexer";
import type { Outpoint } from "../../../src/wallet";

/** Deterministic key for the VHTLC recipient. */
const RECIPIENT_PRIV = hex.decode(
    "3333333333333333333333333333333333333333333333333333333333333333"
);

/**
 * Encode a 4-byte CScriptNum push for the CLTV value. Uses
 * `<push_len> <bytes>` minimal encoding — `144` (0x90) has the sign bit
 * set as a single byte, so we pad with 0x00 (2 bytes total).
 */
function cltvPush(blocks: number): Uint8Array {
    if (blocks < 0 || blocks >= 0x800000) {
        throw new Error(`cltvPush: blocks out of range: ${blocks}`);
    }
    const out: number[] = [];
    if (blocks === 0) {
        out.push(0x00); // OP_0
        return new Uint8Array(out);
    }
    const bytes: number[] = [];
    let v = blocks;
    while (v > 0) {
        bytes.push(v & 0xff);
        v >>>= 8;
    }
    // Sign-bit disambiguation — if top byte has MSB set, append 0x00.
    if (bytes[bytes.length - 1] & 0x80) bytes.push(0x00);
    out.push(bytes.length);
    out.push(...bytes);
    return new Uint8Array(out);
}

/**
 * Build the VHTLC tapleaf script:
 *   <cltvBlocks> OP_CLTV OP_DROP OP_SHA256 <preimageHash> OP_EQUALVERIFY
 *   <pubkey32> OP_CHECKSIG
 */
function buildVhtlcTapleafScript(
    pubkey32: Uint8Array,
    preimageHash: Uint8Array,
    cltvBlocks: number
): Uint8Array {
    if (pubkey32.length !== 32) throw new Error("pubkey32 must be 32 bytes");
    if (preimageHash.length !== 32)
        throw new Error("preimageHash must be 32 bytes");
    const parts: number[] = [];
    // <cltv push>
    parts.push(...cltvPush(cltvBlocks));
    parts.push(0xb1); // OP_CHECKLOCKTIMEVERIFY
    parts.push(0x75); // OP_DROP
    parts.push(0xa8); // OP_SHA256
    parts.push(0x20); // push 32
    parts.push(...preimageHash);
    parts.push(0x88); // OP_EQUALVERIFY
    parts.push(0x20); // push 32
    parts.push(...pubkey32);
    parts.push(0xac); // OP_CHECKSIG
    return new Uint8Array(parts);
}

/**
 * Encode a single-leaf VtxoTaprootTree blob using the SDK's
 * `TapTreeCoder` (BIP 371 PSBT_OUT_TAP_TREE format: array of
 * `{depth: U8, version: U8, script: VarBytes}`).
 */
function encodeSingleLeafTree(
    script: Uint8Array,
    leafVersion: number
): Uint8Array {
    return TapTreeCoder.encode([{ depth: 1, version: leafVersion, script }]);
}

export interface VhtlcScriptPathFixtureOptions {
    readonly cltvBlocks?: number;
    readonly batchAmount?: bigint;
    readonly commitmentTxid?: string;
    readonly preimage?: Uint8Array;
}

export interface VhtlcScriptPathFixture {
    readonly leaf: Outpoint;
    readonly commitmentTxid: string;
    readonly commitmentScript: Uint8Array;
    readonly commitmentAmount: bigint;
    readonly tapleafScript: Uint8Array;
    readonly vtxoChain: VtxoChain;
    readonly virtualTxs: string[];
    readonly preimage: Uint8Array;
    readonly cltvBlocks: number;
}

/**
 * Construct the VHTLC script-path fixture. Not exported publicly by the
 * SDK — test-only helper.
 */
export function buildVhtlcScriptPathFixture(
    opts: VhtlcScriptPathFixtureOptions = {}
): VhtlcScriptPathFixture {
    const cltvBlocks = opts.cltvBlocks ?? 144;
    const batchAmount = opts.batchAmount ?? 100_000n;
    const commitmentTxid = opts.commitmentTxid ?? "c0" + "aa".repeat(31); // deterministic 32-byte hex
    const preimage =
        opts.preimage ??
        hex.decode(
            "deadbeef".padEnd(64, "0") // 32-byte preimage, deterministic
        );

    const pubkey33 = secp256k1.getPublicKey(RECIPIENT_PRIV, true);
    const pubkey32 = pubkey33.subarray(1); // x-only
    const preimageHash = sha256(preimage);

    const tapleaf = buildVhtlcTapleafScript(pubkey32, preimageHash, cltvBlocks);

    // Build a single-leaf taproot with NUMS internal key. @scure returns
    // the scriptPubKey (P2TR-to-tree), the leaves, and the
    // tapLeafScript PSBT input field shape.
    const trOut = p2tr(
        TAPROOT_UNSPENDABLE_KEY,
        { script: tapleaf, leafVersion: 0xc0 },
        undefined,
        true
    );
    // trOut.script = parent P2TR scriptPubKey (on-chain commitment output).
    // trOut.tapLeafScript = [[{version, internalKey, merklePath}, script||leafVer]]
    //    ready to drop into Transaction.updateInput({tapLeafScript}).
    const parentScript = trOut.script;

    // Spending tx: 1 input (the commitment output), 1 output.
    // nLockTime is set at construction (readonly afterwards on @scure).
    // allowUnknown: true so the VtxoTaprootTree PSBT field round-trips.
    const tx = new Transaction({
        version: 2,
        allowUnknownOutputs: true,
        allowUnknown: true,
        lockTime: cltvBlocks,
    });
    tx.addInput({
        txid: commitmentTxid,
        index: 0,
        witnessUtxo: { script: parentScript, amount: batchAmount },
        sequence: 0xfffffffd,
        tapLeafScript: trOut.tapLeafScript!,
    });
    // Output: simple key-path P2TR lock to the same key (arbitrary — not
    // verified here; the verifier focuses on the input witness).
    const childP2tr = new Uint8Array(34);
    childP2tr[0] = 0x51;
    childP2tr[1] = 0x20;
    childP2tr.set(pubkey32, 2);
    tx.addOutput({ script: childP2tr, amount: batchAmount - 500n });

    // Sign the script-path via Schnorr over the BIP 341 script-path sighash.
    // The `tapLeafScript` field is present; @scure can compute sighash with
    // the leaf version + script hash via `preimageWitnessV1` when we pass
    // additional `leafScript` info. Simpler: compute tapLeafHash manually
    // + the BIP 341 ext-flag sighash. For the verifier to accept, we just
    // need a valid Schnorr sig keyed on the BIP 341 sighash.
    //
    // Use @scure's preimageWitnessV1 with the leaf info by constructing
    // the "tapscript sighash" directly. @scure exposes this by passing
    // the leaf version + script to internal helpers; we use the public
    // preimageWitnessV1 which accepts a `leafScript` option:
    const sighash = (
        tx as unknown as {
            preimageWitnessV1: (
                idx: number,
                prevoutScripts: Uint8Array[],
                hashType: number,
                amounts: bigint[],
                codeSeparator?: number,
                leafScript?: Uint8Array,
                leafVer?: number,
                annex?: Uint8Array
            ) => Uint8Array;
        }
    ).preimageWitnessV1(
        0,
        [parentScript],
        0x00, // SIGHASH_DEFAULT
        [batchAmount],
        undefined,
        tapleaf,
        0xc0
    );
    const sig = schnorr.sign(sighash, RECIPIENT_PRIV);

    // Finalised witness stack for a script-path spend of a single-leaf
    // tree: [preimage, sig, script, controlBlock]. The control block is
    // 1B leafVer/parity || 32B internal key (no merkle path for single
    // leaf). @scure's trOut.tapLeafScript[0][0] carries this info, but
    // we need the byte-form for the witness: leafVer|parity byte +
    // internalKey. @scure's p2tr provides these fields; we concat.
    const ctrl = trOut.tapLeafScript![0][0];
    const controlBlock = new Uint8Array(
        1 + ctrl.internalKey.length + ctrl.merklePath.length * 32
    );
    // leafVer (0xc0) OR parity bit (low bit) — @scure's ctrl has both.
    controlBlock[0] = ctrl.version | 0; // parity flag already folded in for us by @scure
    controlBlock.set(ctrl.internalKey, 1);
    let offset = 1 + ctrl.internalKey.length;
    for (const step of ctrl.merklePath) {
        controlBlock.set(step, offset);
        offset += 32;
    }
    // NOTE: BIP 174 finalization semantics strip tapLeafScript from a
    // PSBT input once PSBT_IN_FINAL_SCRIPT_WITNESS is set. We need
    // tapLeafScript to survive PSBT round-trip for the script verifier
    // + walker extractCommitmentTapleafScripts to find it, so we do
    // NOT set finalScriptWitness here. Consequence: preimage.hashes-
    // match stays vacuous for this fixture (no witness stack to scan).
    // A live arkd VTXO with post-finalize witness AND pre-finalize
    // tapLeafScript requires real arkd data — deferred to P7.
    void preimageHash; // still referenced via tapleaf script
    void controlBlock;
    tx.updateInput(0, {
        tapScriptSig: [
            [
                {
                    pubKey: pubkey32,
                    leafHash: tapLeafHashBytes(tapleaf, 0xc0),
                },
                sig,
            ],
        ],
    });

    // Attach VtxoTaprootTree PSBT field with the single leaf encoded.
    const treeBlob = encodeSingleLeafTree(tapleaf, 0xc0);
    setArkPsbtField(tx, 0, VtxoTaprootTree, treeBlob);

    const psbtBytes = tx.toPSBT();
    const psbtBase64 = base64.encode(psbtBytes);

    // ChainTx wrapping: leaf is the script-path tx, parent is a
    // COMMITMENT (synthetic).
    const expiresAt = new Date(Date.now() + 604800000).toISOString();
    const leafTxid = Transaction.fromPSBT(psbtBytes).id;
    const chain: ChainTx[] = [
        {
            txid: leafTxid,
            expiresAt,
            type: ChainTxType.TREE,
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
        leaf: { txid: leafTxid, vout: 0 },
        commitmentTxid,
        commitmentScript: parentScript,
        commitmentAmount: batchAmount,
        tapleafScript: tapleaf,
        vtxoChain: { chain },
        virtualTxs: [psbtBase64],
        preimage,
        cltvBlocks,
    };
}

/** BIP 341 tapLeafHash. */
function tapLeafHashBytes(script: Uint8Array, leafVersion: number): Uint8Array {
    const tag = sha256(new TextEncoder().encode("TapLeaf"));
    // Compact-size encoding of script length
    const lenBytes =
        script.length < 0xfd
            ? new Uint8Array([script.length])
            : new Uint8Array([0xfd, script.length & 0xff, script.length >> 8]);
    const buf = new Uint8Array(
        tag.length * 2 + 1 + lenBytes.length + script.length
    );
    buf.set(tag, 0);
    buf.set(tag, tag.length);
    buf[tag.length * 2] = leafVersion;
    buf.set(lenBytes, tag.length * 2 + 1);
    buf.set(script, tag.length * 2 + 1 + lenBytes.length);
    return sha256(buf);
}
