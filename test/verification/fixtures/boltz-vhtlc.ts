/**
 * Boltz-shape VHTLC fixture — assignment §3.2.3 demonstration.
 *
 * Uses the SDK's real `VHTLC.Script` class to build a Boltz-style
 * Virtual HTLC contract:
 *   - 6 tapleaves (claim / refund / refundWithoutReceiver /
 *     unilateralClaim / unilateralRefund /
 *     unilateralRefundWithoutReceiver)
 *   - claim leaf carries the canonical Boltz preimage check:
 *     `OP_HASH160 <ripemd160(sha256(preimage))> OP_EQUALVERIFY` +
 *     n-of-n MuSig over receiver+server.
 *
 * Spends the claim leaf (script-path), so the verifier exercises:
 *   - `script.control-block-valid`  on a real VHTLC tapleaf
 *   - `script.merkle-root-matches`  on a 6-leaf taptree (multi-leaf
 *     merkle path — exercises tapBranchHash beyond M1's single leaf)
 *   - `script.internal-key-is-nums` on the NUMS internal key VHTLC uses
 *   - `script.vtxotaprootree-valid` on the full 6-leaf VtxoTaprootTree
 *   - `preimage.conditions-scanned` finds the **HASH160** commitment
 *     (M1 covered SHA256; this exercises the OP_HASH160 path)
 *   - `preimage.hashes-match` reports `pending` (no finalScriptWitness
 *     attached — same BIP 174 constraint as M1)
 *
 * This is the §3.2.3 "demonstrate on Boltz" deliverable. Live testnet
 * Boltz capture not required — VHTLC.Script produces the same on-wire
 * bytes Boltz would; we're verifying the SDK's contract is correctly
 * recognised by our pipeline.
 */

import { base64, hex } from "@scure/base";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { Transaction } from "@scure/btc-signer/transaction.js";
import {
    setArkPsbtField,
    VtxoTaprootTree,
    ConditionWitness,
} from "../../../src/utils/unknownFields";
import { VHTLC } from "../../../src/script/vhtlc";
import type { ChainTx, VtxoChain } from "../../../src/providers/indexer";
import { ChainTxType } from "../../../src/providers/indexer";
import type { Outpoint } from "../../../src/wallet";

/** Deterministic Boltz-fixture keys. */
const SENDER_PRIV = hex.decode(
    "4444444444444444444444444444444444444444444444444444444444444444"
);
const RECEIVER_PRIV = hex.decode(
    "5555555555555555555555555555555555555555555555555555555555555555"
);
const SERVER_PRIV = hex.decode(
    "6666666666666666666666666666666666666666666666666666666666666666"
);

function xOnly(priv: Uint8Array): Uint8Array {
    return secp256k1.getPublicKey(priv, true).subarray(1);
}

export interface BoltzVhtlcFixture {
    readonly leaf: Outpoint;
    readonly commitmentTxid: string;
    readonly commitmentScript: Uint8Array;
    readonly commitmentAmount: bigint;
    readonly preimage: Uint8Array;
    readonly preimageHash160: Uint8Array;
    readonly vtxoChain: VtxoChain;
    readonly virtualTxs: string[];
    readonly vhtlc: VHTLC.Script;
}

/**
 * Build a Boltz-shape VHTLC fixture. The leaf tx spends the
 * commitment via the **claim** path (preimage + receiver+server sigs).
 */
export function buildBoltzVhtlcFixture(opts?: {
    refundLocktime?: bigint;
    batchAmount?: bigint;
    commitmentTxid?: string;
}): BoltzVhtlcFixture {
    const refundLocktime = opts?.refundLocktime ?? 200n;
    const batchAmount = opts?.batchAmount ?? 100_000n;
    const commitmentTxid = opts?.commitmentTxid ?? "b0" + "12".repeat(31); // deterministic
    // 32-byte deterministic preimage; HASH160 = ripemd160(sha256(.))
    const preimage = hex.decode("b0".repeat(32));
    const preimageHash160 = ripemd160(sha256(preimage));

    const sender = xOnly(SENDER_PRIV);
    const receiver = xOnly(RECEIVER_PRIV);
    const server = xOnly(SERVER_PRIV);

    const vhtlc = new VHTLC.Script({
        sender,
        receiver,
        server,
        preimageHash: preimageHash160,
        refundLocktime,
        unilateralClaimDelay: { type: "blocks", value: 100n },
        unilateralRefundDelay: { type: "blocks", value: 102n },
        unilateralRefundWithoutReceiverDelay: { type: "blocks", value: 103n },
    });

    const parentScript = vhtlc.pkScript; // P2TR scriptPubKey
    const claimLeaf = vhtlc.claim();

    // Build a tx that spends the VHTLC via the claim leaf.
    // allowUnknown so the VtxoTaprootTree PSBT field round-trips.
    const tx = new Transaction({
        version: 2,
        allowUnknownOutputs: true,
        allowUnknown: true,
    });
    tx.addInput({
        txid: commitmentTxid,
        index: 0,
        witnessUtxo: { script: parentScript, amount: batchAmount },
        sequence: 0xfffffffd,
        tapLeafScript: [claimLeaf],
    });
    // Output: simple key-path P2TR back to the receiver.
    const outScript = new Uint8Array(34);
    outScript[0] = 0x51;
    outScript[1] = 0x20;
    outScript.set(receiver, 2);
    tx.addOutput({ script: outScript, amount: batchAmount - 500n });

    // Sign the script-path with both receiver and server (n-of-n claim
    // path requires both sigs).
    const claimScriptBytes = claimLeaf[1].subarray(0, claimLeaf[1].length - 1);
    const claimLeafVersion = claimLeaf[1][claimLeaf[1].length - 1];
    const sighash = (
        tx as unknown as {
            preimageWitnessV1: (
                idx: number,
                prevoutScripts: Uint8Array[],
                hashType: number,
                amounts: bigint[],
                codeSeparator?: number,
                leafScript?: Uint8Array,
                leafVer?: number
            ) => Uint8Array;
        }
    ).preimageWitnessV1(
        0,
        [parentScript],
        0x00,
        [batchAmount],
        undefined,
        claimScriptBytes,
        claimLeafVersion
    );
    const receiverSig = schnorr.sign(sighash, RECEIVER_PRIV);
    const serverSig = schnorr.sign(sighash, SERVER_PRIV);

    // tapLeafHash for both tapScriptSig entries.
    const leafHash = tapLeafHashBytes(claimScriptBytes, claimLeafVersion);
    tx.updateInput(0, {
        tapScriptSig: [
            [{ pubKey: receiver, leafHash }, receiverSig],
            [{ pubKey: server, leafHash }, serverSig],
        ],
    });

    // Attach the full 6-leaf VHTLC tree as the VtxoTaprootTree PSBT
    // unknown field. `vhtlc.encode()` produces the on-wire taptree blob
    // (matches what arkd would emit).
    const treeBlob = vhtlc.encode();
    setArkPsbtField(tx, 0, VtxoTaprootTree, treeBlob);

    // Attach the preimage via ConditionWitness — this is how the SDK
    // stores preimages on VHTLC claim inputs during intent construction
    // (src/contracts/handlers/vhtlc.ts:114 → src/intent/index.ts:312).
    // Pre-signed txs don't carry finalScriptWitness (BIP 174
    // finalization happens at broadcast), so ConditionWitness is the
    // preimage source for the preimage verifier.
    setArkPsbtField(tx, 0, ConditionWitness, [preimage]);

    const psbtBytes = tx.toPSBT();
    const psbtBase64 = base64.encode(psbtBytes);
    const leafTxid = Transaction.fromPSBT(psbtBytes).id;

    const expiresAt = new Date(Date.now() + 604800000).toISOString();
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
        preimage,
        preimageHash160,
        vtxoChain: { chain },
        virtualTxs: [psbtBase64],
        vhtlc,
    };
}

/** BIP 341 tapLeafHash. */
function tapLeafHashBytes(script: Uint8Array, leafVersion: number): Uint8Array {
    const tag = sha256(new TextEncoder().encode("TapLeaf"));
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
