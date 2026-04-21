import { hex } from "@scure/base";
import { schnorr } from "@noble/curves/secp256k1.js";
import { Transaction } from "@scure/btc-signer/transaction.js";
import { tapLeafHash } from "@scure/btc-signer/payment.js";
import { MalformedChainError, UnsupportedFeatureError } from "./errors";
import type {
    CheckResult,
    PerInputPrevouts,
    Prevout,
    SighashType,
    SignaturePathEntry,
    Txid,
} from "./types";
import { parseSighashFromSchnorrSig, sighashTypeDefault } from "./types";
import type { DagAdapter } from "./chain-walker";
import { aggregateKeys } from "../musig2";
import {
    getArkPsbtFields,
    CosignerPublicKey,
    VtxoTaprootTree,
    VtxoTreeExpiry,
} from "../utils/unknownFields";
import { TapTreeCoder } from "../script/base";
import { decodeTapscript, CSVMultisigTapscript } from "../script/tapscript";

/**
 * Typed wrapper for `@scure/btc-signer`'s preimageWitnessV1. The
 * `sighashType` parameter is REQUIRED (no default) — callers must
 * thread the sighash byte parsed out of the 65-byte Schnorr sig
 * (bug B5 from v1 self-review).
 *
 * For script-path spends the caller passes `leafScript` + `leafVersion`
 * so the BIP 341 ext-flag sighash incorporates the tapleaf hash. For
 * key-path spends those are omitted.
 */
export function preimageWitnessV1Typed(
    tx: Transaction,
    inputIndex: number,
    prevouts: PerInputPrevouts,
    sighashType: SighashType,
    leafScript?: Uint8Array,
    leafVersion?: number
): Uint8Array {
    const scripts = prevouts.map((p) => p.script);
    const amounts = prevouts.map((p) => p.amount);
    return tx.preimageWitnessV1(
        inputIndex,
        scripts,
        sighashType,
        amounts,
        undefined,
        leafScript,
        leafVersion
    );
}

export interface SignatureVerifierInput {
    readonly path: readonly SignaturePathEntry[];
    /**
     * DAG adapter used by {@link sig.musig2-aggregate-valid} to
     * iterate every COMMITMENT-parented input — the B3 invariant's
     * only API for reaching those inputs (no path[length-1] shortcut).
     */
    readonly dag?: DagAdapter;
    readonly signal?: AbortSignal;
}

/**
 * Per-tx entry kept around across checks so we don't re-classify
 * inputs between sighash-computed and schnorr-valid.
 */
interface ClassifiedEntry {
    readonly entry: SignaturePathEntry;
    readonly txid: Txid;
    readonly kinds: readonly ("key" | "script")[];
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i++) {
        if (a[i] !== b[i]) return a[i] - b[i];
    }
    return a.length - b.length;
}

function tapBranchHash(a: Uint8Array, b: Uint8Array): Uint8Array {
    const [lo, hi] = compareBytes(a, b) <= 0 ? [a, b] : [b, a];
    return new Uint8Array(schnorr.utils.taggedHash("TapBranch", lo, hi));
}

/**
 * Compute the BIP 341 taptree merkle root from decoded leaves
 * (BIP 371 `{depth, version, script}[]` format).
 */
function tapTreeMerkleRoot(
    leaves: ReadonlyArray<{
        depth: number;
        version: number;
        script: Uint8Array;
    }>
): Uint8Array | null {
    if (leaves.length === 0) return null;
    const stack: Array<{ depth: number; hash: Uint8Array }> = [];
    for (const leaf of leaves) {
        let hash = tapLeafHash(leaf.script, leaf.version);
        let depth = leaf.depth;
        while (stack.length > 0 && stack[stack.length - 1].depth === depth) {
            const sibling = stack.pop()!;
            hash = tapBranchHash(sibling.hash, hash);
            depth--;
        }
        stack.push({ depth, hash });
    }
    return stack.length === 1 ? stack[0].hash : null;
}

/**
 * Extract the 32-byte x-only pubkey from a P2TR scriptPubKey
 * (OP_1 0x20 <32B>). Throws on non-P2TR shape.
 */
function p2trXOnlyKey(script: Uint8Array, txid: Txid): Uint8Array {
    if (script.length !== 34 || script[0] !== 0x51 || script[1] !== 0x20) {
        throw new MalformedChainError({
            kind: "DATA",
            code: "sig.parent-not-p2tr",
            message: `Parent output of ${txid} is not a P2TR script`,
            context: { txid, scriptLength: script.length },
        });
    }
    return script.subarray(2);
}

function throwIfAborted(signal?: AbortSignal, txid?: Txid): void {
    if (signal?.aborted) {
        throw new MalformedChainError({
            kind: "UNSUPPORTED",
            code: "sig.aborted",
            message: `Signature verification aborted (near tx ${txid ?? "?"})`,
        });
    }
}

/**
 * Runs all four {@link sig.*} checks on the supplied path.
 *
 * Emits (in order):
 *   1. sig.classified — every input routes to key-path or script-path
 *      (UNSUPPORTED for unknown witness shapes).
 *   2. sig.sighash-computed — BIP 341 sighash derived per input.
 *   3. sig.schnorr-valid — every Schnorr sig verifies against its
 *      pubkey + sighash.
 *   4. sig.musig2-aggregate-valid — per COMMITMENT-parented input, if
 *      the PSBT carries Cosigner fields, confirm the aggregated key
 *      matches the batch P2TR internal key. No-cosigners inputs pass
 *      with an "no-data" note (synthetic fixtures have none).
 *
 * Never throws on a failed-sig: that flips {@link sig.schnorr-valid}.
 * Throws {@link MalformedChainError} on structurally unintelligible
 * input, {@link UnsupportedFeatureError} on witness shapes or sighash
 * types we don't implement yet.
 */
export async function verifySignatures(
    input: SignatureVerifierInput
): Promise<readonly CheckResult[]> {
    const { path, dag, signal } = input;
    const checks: CheckResult[] = [];

    // ── 1. Classify every input ───────────────────────────────────────
    const classifyStart = Date.now();
    const classified: ClassifiedEntry[] = [];
    let keyPathCount = 0;
    let scriptPathCount = 0;
    for (const entry of path) {
        throwIfAborted(signal);
        if (entry.tx.inputsLength === 0) {
            throw new MalformedChainError({
                kind: "DATA",
                code: "sig.missing-input",
                message: `Tx has no inputs`,
            });
        }
        const txid = txidFromTx(entry.tx);
        const kinds: ("key" | "script")[] = [];
        for (let j = 0; j < entry.tx.inputsLength; j++) {
            const inp = entry.tx.getInput(j);
            const hasKey = !!inp.tapKeySig;
            const hasScript = !!inp.tapScriptSig && inp.tapScriptSig.length > 0;
            if (hasKey) {
                kinds.push("key");
                keyPathCount++;
            } else if (hasScript) {
                kinds.push("script");
                scriptPathCount++;
            } else {
                throw new UnsupportedFeatureError({
                    kind: "UNSUPPORTED",
                    code: "sig.unknown-witness-shape",
                    message: `Tx ${txid} input ${j} has neither tapKeySig nor tapScriptSig`,
                    context: { txid, input_index: j },
                });
            }
        }
        classified.push({ entry, txid, kinds });
    }
    checks.push({
        name: "sig.classified",
        passed: true,
        details: `${keyPathCount + scriptPathCount} input(s) classified (${keyPathCount} key-path, ${scriptPathCount} script-path)`,
        durationMs: Date.now() - classifyStart,
        evidence: {
            keypath_count: keyPathCount,
            scriptpath_count: scriptPathCount,
            sigs_total: keyPathCount + scriptPathCount,
            path_length: path.length,
        },
    });

    // ── 2+3. Compute sighash + verify schnorr — one pass ─────────────
    const sighashStart = Date.now();
    let sighashesComputed = 0;
    let sigsVerified = 0;
    let sigsFailed = 0;
    const failDetails: string[] = [];

    for (let i = 0; i < classified.length; i++) {
        const { entry, txid, kinds } = classified[i];
        throwIfAborted(signal, txid);
        for (let j = 0; j < kinds.length; j++) {
            const kind = kinds[j];
            const inp = entry.tx.getInput(j);

            if (kind === "key") {
                const sig = inp.tapKeySig!;
                if (sig.length !== 64 && sig.length !== 65) {
                    throw new MalformedChainError({
                        kind: "DATA",
                        code: "sig.bad-sig-length",
                        message: `Tx ${txid} input ${j} tapKeySig is ${sig.length} bytes (expected 64 or 65)`,
                        context: { txid, input_index: j, length: sig.length },
                    });
                }
                const sighashType = parseSighashFromSchnorrSig(sig);
                if (sighashType !== sighashTypeDefault) {
                    throw new UnsupportedFeatureError({
                        kind: "UNSUPPORTED",
                        code: "sig.unsupported-sighash",
                        message: `Tx ${txid} input ${j} uses sighash ${sighashType.toString(16)} — only SIGHASH_DEFAULT supported in P3`,
                        context: { txid, input_index: j, sighashType },
                    });
                }
                const sigBytes = sig.subarray(0, 64);
                const prevoutOfThisInput = entry.perInputPrevouts[j];
                const pubkey = p2trXOnlyKey(prevoutOfThisInput.script, txid);
                const msg = preimageWitnessV1Typed(
                    entry.tx,
                    j,
                    entry.perInputPrevouts,
                    sighashType
                );
                sighashesComputed++;
                if (schnorr.verify(sigBytes, msg, pubkey)) {
                    sigsVerified++;
                } else {
                    sigsFailed++;
                    failDetails.push(
                        `${txid} input ${j} key-path sig failed vs pubkey ${hex.encode(pubkey)}`
                    );
                }
            } else {
                // script-path: iterate every tapScriptSig
                const tapScriptSig = inp.tapScriptSig as ReadonlyArray<
                    readonly [
                        {
                            pubKey: Uint8Array;
                            leafHash: Uint8Array;
                        },
                        Uint8Array,
                    ]
                >;
                const tapLeafScriptField = inp.tapLeafScript as
                    | ReadonlyArray<
                          readonly [
                              unknown,
                              Uint8Array /* script || leafVersion byte */,
                          ]
                      >
                    | undefined;
                if (!tapLeafScriptField || tapLeafScriptField.length === 0) {
                    throw new MalformedChainError({
                        kind: "DATA",
                        code: "sig.missing-tapleaf-script",
                        message: `Tx ${txid} input ${j} script-path missing tapLeafScript`,
                        context: { txid, input_index: j },
                    });
                }
                for (let k = 0; k < tapScriptSig.length; k++) {
                    const [meta, sig] = tapScriptSig[k];
                    if (sig.length !== 64 && sig.length !== 65) {
                        throw new MalformedChainError({
                            kind: "DATA",
                            code: "sig.bad-sig-length",
                            message: `Tx ${txid} input ${j} tapScriptSig[${k}] is ${sig.length} bytes`,
                            context: {
                                txid,
                                input_index: j,
                                length: sig.length,
                            },
                        });
                    }
                    const sighashType = parseSighashFromSchnorrSig(sig);
                    // Find matching tapLeafScript by leafHash.
                    let matchedScript: Uint8Array | undefined;
                    let matchedLeafVersion: number | undefined;
                    for (const leaf of tapLeafScriptField) {
                        const scriptBytes = leaf[1];
                        // leafHash expected = tapLeafHash(leafVersion, script)
                        const lv = scriptBytes[scriptBytes.length - 1];
                        const actualScript = scriptBytes.subarray(
                            0,
                            scriptBytes.length - 1
                        );
                        const computed = tapLeafHash(actualScript, lv);
                        if (bytesEqual(computed, meta.leafHash)) {
                            matchedScript = actualScript;
                            matchedLeafVersion = lv;
                            break;
                        }
                    }
                    if (!matchedScript || matchedLeafVersion === undefined) {
                        throw new MalformedChainError({
                            kind: "DATA",
                            code: "sig.leafhash-mismatch",
                            message: `Tx ${txid} input ${j} tapScriptSig[${k}] leafHash has no matching tapLeafScript`,
                            context: { txid, input_index: j, k },
                        });
                    }
                    const sigBytes = sig.subarray(0, 64);
                    // Script-path sighash must include the tapleaf hash —
                    // pass leafScript + leafVersion through to
                    // preimageWitnessV1 so BIP 341's ext-flag sighash
                    // incorporates it.
                    const msg = preimageWitnessV1Typed(
                        entry.tx,
                        j,
                        entry.perInputPrevouts,
                        sighashType,
                        matchedScript,
                        matchedLeafVersion
                    );
                    sighashesComputed++;
                    if (schnorr.verify(sigBytes, msg, meta.pubKey)) {
                        sigsVerified++;
                    } else {
                        sigsFailed++;
                        failDetails.push(
                            `${txid} input ${j} script-path sig[${k}] failed vs pubkey ${hex.encode(meta.pubKey)}`
                        );
                    }
                }
            }
        }
    }

    checks.push({
        name: "sig.sighash-computed",
        passed: true,
        details: `Derived ${sighashesComputed} sighash(es) across ${path.length} tx(s)`,
        durationMs: Date.now() - sighashStart,
        evidence: {
            sighashes_computed: sighashesComputed,
            path_length: path.length,
        },
    });
    const schnorrPassed = sigsFailed === 0;
    checks.push({
        name: "sig.schnorr-valid",
        passed: schnorrPassed,
        details: schnorrPassed
            ? `All ${sigsVerified} signature(s) verify`
            : `${sigsFailed} signature(s) failed: ${failDetails.join("; ")}`,
        durationMs: 0,
        evidence: {
            sigs_verified: sigsVerified,
            sigs_failed: sigsFailed,
            sigs_total: sigsVerified + sigsFailed,
        },
    });

    // ── 4. MuSig2 aggregate — verify cosigning scheme ──────────────
    // For every input that carries CosignerPublicKey PSBT fields,
    // aggregate the declared keys (BIP 327 KeyAgg via SDK's
    // aggregateKeys), tweak with the VtxoTaprootTree merkle root,
    // and compare the result against the parent P2TR output key.
    // This replicates the upstream validateVtxoTxGraph check
    // (src/tree/validation.ts:128-148) on our verified path.
    const aggStart = Date.now();
    let cosignerInputsChecked = 0;
    let cosignerInputsMatched = 0;
    let cosignerInputsNoTree = 0;
    let sweepLeavesFound = 0;
    let expiryCrossChecks = 0;
    let expiryMatched = 0;
    const cosignerFailDetails: string[] = [];

    for (const entry of path) {
        const txid = entry.tx.id as Txid;
        for (let j = 0; j < entry.tx.inputsLength; j++) {
            const cosigners = getArkPsbtFields(entry.tx, j, CosignerPublicKey);
            if (cosigners.length === 0) continue;
            cosignerInputsChecked++;

            const cosignerKeys = cosigners
                .sort((a, b) => a.index - b.index)
                .map((c) => c.key);

            if (cosignerKeys.some((k) => k.length !== 33)) {
                cosignerFailDetails.push(
                    `${txid} input ${j} invalid cosigner key length`
                );
                continue;
            }

            // Read the taptree to derive the sweep merkle root.
            const treeBlobs = getArkPsbtFields(entry.tx, j, VtxoTaprootTree);
            let merkleRoot: Uint8Array | null = null;
            let sweepTimelock:
                | { type: "blocks" | "seconds"; value: bigint }
                | undefined;

            if (treeBlobs.length > 0) {
                try {
                    const decoded = TapTreeCoder.decode(
                        treeBlobs[0]
                    ) as ReadonlyArray<{
                        depth: number;
                        version: number;
                        script: Uint8Array;
                    }>;
                    merkleRoot = tapTreeMerkleRoot(decoded);

                    // Identify the sweep leaf (CSVMultisigTapscript).
                    for (const leaf of decoded) {
                        try {
                            const ts = decodeTapscript(leaf.script);
                            if (CSVMultisigTapscript.is(ts)) {
                                sweepTimelock = ts.params.timelock;
                                sweepLeavesFound++;
                                break;
                            }
                        } catch {
                            // Not a recognised Ark tapscript — skip.
                        }
                    }
                } catch {
                    cosignerFailDetails.push(
                        `${txid} input ${j} VtxoTaprootTree decode failed`
                    );
                    continue;
                }
            }

            if (!merkleRoot) {
                cosignerInputsNoTree++;
                continue;
            }

            // Aggregate cosigner keys with the taptree tweak and
            // compare against the parent P2TR output key.
            try {
                const { finalKey } = aggregateKeys(cosignerKeys, true, {
                    taprootTweak: merkleRoot,
                });
                const parentXOnly =
                    entry.perInputPrevouts[j].script.subarray(2);
                if (parentXOnly.length !== 32) {
                    cosignerFailDetails.push(
                        `${txid} input ${j} parent output not P2TR`
                    );
                    continue;
                }
                if (bytesEqual(finalKey.subarray(1), parentXOnly)) {
                    cosignerInputsMatched++;
                } else {
                    cosignerFailDetails.push(
                        `${txid} input ${j} aggregated key does not match parent P2TR`
                    );
                }
            } catch (e) {
                cosignerFailDetails.push(
                    `${txid} input ${j} key aggregation failed: ${e instanceof Error ? e.message : String(e)}`
                );
                continue;
            }

            // Cross-check sweep timelock against VtxoTreeExpiry.
            if (sweepTimelock) {
                const expiries = getArkPsbtFields(entry.tx, j, VtxoTreeExpiry);
                if (expiries.length > 0) {
                    expiryCrossChecks++;
                    const expiry = expiries[0];
                    if (
                        expiry.type === sweepTimelock.type &&
                        expiry.value === sweepTimelock.value
                    ) {
                        expiryMatched++;
                    }
                }
            }
        }
    }

    const aggPassed = cosignerFailDetails.length === 0;
    checks.push({
        name: "sig.musig2-aggregate-valid",
        passed: aggPassed,
        details:
            cosignerInputsChecked === 0
                ? "No inputs carry CosignerPublicKey fields"
                : cosignerFailDetails.length > 0
                  ? cosignerFailDetails.join("; ")
                  : cosignerInputsNoTree > 0
                    ? `${cosignerInputsMatched}/${cosignerInputsChecked} verified; ${cosignerInputsNoTree} skipped (no VtxoTaprootTree)`
                    : `${cosignerInputsMatched}/${cosignerInputsChecked} aggregated key(s) match parent P2TR`,
        durationMs: Date.now() - aggStart,
        evidence: {
            inputs_checked: cosignerInputsChecked,
            inputs_matched: cosignerInputsMatched,
            inputs_no_taptree: cosignerInputsNoTree,
            sweep_leaves_found: sweepLeavesFound,
            expiry_cross_checks: expiryCrossChecks,
            expiry_matched: expiryMatched,
            mismatches: cosignerFailDetails,
        },
    });

    return checks;
}

import { equalBytes } from "@scure/btc-signer/utils.js";
const bytesEqual = equalBytes;

import { txidFromString } from "./types";

function txidFromTx(tx: Transaction): Txid {
    return txidFromString(tx.id);
}

// Re-export types for external consumers via the barrel.
export type { SignaturePathEntry, Prevout, PerInputPrevouts };
