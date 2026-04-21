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
import {
    parseSighashFromSchnorrSig,
    sighashTypeDefault,
    txidFromString,
} from "./types";
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
import {
    bytesEqual,
    tapTreeMerkleRoot,
    throwIfAborted,
    MAX_TAPTREE_BLOB_BYTES,
} from "./utils";

// ── Public API ──────────────────────────────────────────────────────

/**
 * Typed wrapper for `@scure/btc-signer`'s preimageWitnessV1.
 * `sighashType` is REQUIRED — callers must thread the sighash byte
 * parsed from the Schnorr sig (bug B5 from v1 self-review).
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
    readonly dag?: DagAdapter;
    readonly signal?: AbortSignal;
}

/**
 * Runs all four `sig.*` checks on the supplied path. Never throws on
 * a failed signature — that flips `sig.schnorr-valid`.
 */
export async function verifySignatures(
    input: SignatureVerifierInput
): Promise<readonly CheckResult[]> {
    const { path, signal } = input;
    const checks: CheckResult[] = [];

    const { classified, check: classifyCheck } = classifyInputs(path, signal);
    checks.push(classifyCheck);

    const { checks: schnorrChecks } = verifySighashesAndSchnorr(
        classified,
        signal
    );
    checks.push(...schnorrChecks);

    checks.push(verifyMusig2Aggregate(path));

    return checks;
}

// ── Internal types ──────────────────────────────────────────────────

interface ClassifiedEntry {
    readonly entry: SignaturePathEntry;
    readonly txid: Txid;
    readonly kinds: readonly ("key" | "script")[];
}

// ── Helpers ─────────────────────────────────────────────────────────

function txidFromTx(tx: Transaction): Txid {
    return txidFromString(tx.id);
}

function p2trXOnlyKeyOrThrow(script: Uint8Array, txid: Txid): Uint8Array {
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

// ── Step 1: Classify every input ────────────────────────────────────

function classifyInputs(
    path: readonly SignaturePathEntry[],
    signal?: AbortSignal
): { classified: ClassifiedEntry[]; check: CheckResult } {
    const start = Date.now();
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
            if (inp.tapKeySig) {
                kinds.push("key");
                keyPathCount++;
            } else if (
                Array.isArray(inp.tapScriptSig) &&
                inp.tapScriptSig.length > 0
            ) {
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

    return {
        classified,
        check: {
            name: "sig.classified",
            passed: true,
            details: `${keyPathCount + scriptPathCount} input(s) classified (${keyPathCount} key-path, ${scriptPathCount} script-path)`,
            durationMs: Date.now() - start,
            evidence: {
                keypath_count: keyPathCount,
                scriptpath_count: scriptPathCount,
                sigs_total: keyPathCount + scriptPathCount,
                path_length: classified.length,
            },
        },
    };
}

// ── Steps 2+3: Sighash computation + Schnorr verification ──────────

function verifySighashesAndSchnorr(
    classified: readonly ClassifiedEntry[],
    signal?: AbortSignal
): { checks: [CheckResult, CheckResult] } {
    const start = Date.now();
    let computed = 0;
    let verified = 0;
    let failed = 0;
    const failDetails: string[] = [];

    for (const { entry, txid, kinds } of classified) {
        throwIfAborted(signal, txid);
        for (let j = 0; j < kinds.length; j++) {
            const inp = entry.tx.getInput(j);

            if (kinds[j] === "key") {
                const result = verifyKeyPathSig(entry, txid, j, inp);
                computed++;
                if (result.ok) verified++;
                else {
                    failed++;
                    failDetails.push(result.detail);
                }
            } else {
                const result = verifyScriptPathSigs(entry, txid, j, inp);
                computed += result.computed;
                verified += result.verified;
                failed += result.failed;
                failDetails.push(...result.failDetails);
            }
        }
    }

    return {
        checks: [
            {
                name: "sig.sighash-computed",
                passed: true,
                details: `Derived ${computed} sighash(es) across ${classified.length} tx(s)`,
                durationMs: Date.now() - start,
                evidence: {
                    sighashes_computed: computed,
                    path_length: classified.length,
                },
            },
            {
                name: "sig.schnorr-valid",
                passed: failed === 0,
                details:
                    failed === 0
                        ? `All ${verified} signature(s) verify`
                        : `${failed} signature(s) failed: ${failDetails.join("; ")}`,
                durationMs: 0,
                evidence: {
                    sigs_verified: verified,
                    sigs_failed: failed,
                    sigs_total: verified + failed,
                },
            },
        ],
    };
}

function verifyKeyPathSig(
    entry: SignaturePathEntry,
    txid: Txid,
    j: number,
    inp: ReturnType<Transaction["getInput"]>
): { ok: boolean; detail: string } {
    const sig = inp.tapKeySig!;
    if (sig.length !== 64 && sig.length !== 65) {
        throw new MalformedChainError({
            kind: "DATA",
            code: "sig.bad-sig-length",
            message: `Tx ${txid} input ${j} tapKeySig is ${sig.length} bytes`,
            context: { txid, input_index: j, length: sig.length },
        });
    }
    const sighashType = parseSighashFromSchnorrSig(sig);
    if (sighashType !== sighashTypeDefault) {
        throw new UnsupportedFeatureError({
            kind: "UNSUPPORTED",
            code: "sig.unsupported-sighash",
            message: `Tx ${txid} input ${j} uses sighash ${sighashType.toString(16)}`,
            context: { txid, input_index: j, sighashType },
        });
    }
    const pubkey = p2trXOnlyKeyOrThrow(entry.perInputPrevouts[j].script, txid);
    const msg = preimageWitnessV1Typed(
        entry.tx,
        j,
        entry.perInputPrevouts,
        sighashType
    );
    const ok = schnorr.verify(sig.subarray(0, 64), msg, pubkey);
    return {
        ok,
        detail: ok
            ? ""
            : `${txid} input ${j} key-path sig failed vs pubkey ${hex.encode(pubkey)}`,
    };
}

function verifyScriptPathSigs(
    entry: SignaturePathEntry,
    txid: Txid,
    j: number,
    inp: ReturnType<Transaction["getInput"]>
): {
    computed: number;
    verified: number;
    failed: number;
    failDetails: string[];
} {
    const tapScriptSig = inp.tapScriptSig;
    if (!Array.isArray(tapScriptSig) || tapScriptSig.length === 0) {
        throw new MalformedChainError({
            kind: "DATA",
            code: "sig.missing-tapscriptsig",
            message: `Tx ${txid} input ${j} script-path missing tapScriptSig`,
            context: { txid, input_index: j },
        });
    }
    const tapLeafScriptField = inp.tapLeafScript;
    if (!Array.isArray(tapLeafScriptField) || tapLeafScriptField.length === 0) {
        throw new MalformedChainError({
            kind: "DATA",
            code: "sig.missing-tapleaf-script",
            message: `Tx ${txid} input ${j} script-path missing tapLeafScript`,
            context: { txid, input_index: j },
        });
    }

    let computed = 0;
    let verified = 0;
    let failed = 0;
    const failDetails: string[] = [];

    for (let k = 0; k < tapScriptSig.length; k++) {
        const pair = tapScriptSig[k];
        if (
            !Array.isArray(pair) ||
            pair.length < 2 ||
            !pair[0]?.pubKey ||
            !pair[0]?.leafHash ||
            !(pair[1] instanceof Uint8Array)
        ) {
            throw new MalformedChainError({
                kind: "DATA",
                code: "sig.malformed-tapscriptsig",
                message: `Tx ${txid} input ${j} tapScriptSig[${k}] has unexpected shape`,
                context: { txid, input_index: j, k },
            });
        }
        const meta = pair[0] as { pubKey: Uint8Array; leafHash: Uint8Array };
        const sig = pair[1] as Uint8Array;

        if (sig.length !== 64 && sig.length !== 65) {
            throw new MalformedChainError({
                kind: "DATA",
                code: "sig.bad-sig-length",
                message: `Tx ${txid} input ${j} tapScriptSig[${k}] is ${sig.length} bytes`,
                context: { txid, input_index: j, length: sig.length },
            });
        }

        const { matchedScript, matchedLeafVersion } = findMatchingLeaf(
            tapLeafScriptField,
            meta.leafHash,
            txid,
            j,
            k
        );

        const sighashType = parseSighashFromSchnorrSig(sig);
        const msg = preimageWitnessV1Typed(
            entry.tx,
            j,
            entry.perInputPrevouts,
            sighashType,
            matchedScript,
            matchedLeafVersion
        );
        computed++;
        if (schnorr.verify(sig.subarray(0, 64), msg, meta.pubKey)) {
            verified++;
        } else {
            failed++;
            failDetails.push(
                `${txid} input ${j} script-path sig[${k}] failed vs pubkey ${hex.encode(meta.pubKey)}`
            );
        }
    }

    return { computed, verified, failed, failDetails };
}

function findMatchingLeaf(
    tapLeafScriptField: readonly unknown[],
    leafHash: Uint8Array,
    txid: Txid,
    j: number,
    k: number
): { matchedScript: Uint8Array; matchedLeafVersion: number } {
    for (const leaf of tapLeafScriptField) {
        if (
            !Array.isArray(leaf) ||
            !(leaf[1] instanceof Uint8Array) ||
            leaf[1].length < 2
        )
            continue;
        const scriptBytes = leaf[1] as Uint8Array;
        const lv = scriptBytes[scriptBytes.length - 1];
        const actualScript = scriptBytes.subarray(0, scriptBytes.length - 1);
        if (bytesEqual(tapLeafHash(actualScript, lv), leafHash)) {
            return { matchedScript: actualScript, matchedLeafVersion: lv };
        }
    }
    throw new MalformedChainError({
        kind: "DATA",
        code: "sig.leafhash-mismatch",
        message: `Tx ${txid} input ${j} tapScriptSig[${k}] leafHash has no matching tapLeafScript`,
        context: { txid, input_index: j, k },
    });
}

// ── Step 4: MuSig2 aggregate — verify cosigning scheme ──────────────

function verifyMusig2Aggregate(
    path: readonly SignaturePathEntry[]
): CheckResult {
    const start = Date.now();
    let checked = 0;
    let matched = 0;
    let noTree = 0;
    let sweepLeavesFound = 0;
    let expiryCrossChecks = 0;
    let expiryMatched = 0;
    const failures: string[] = [];

    for (const entry of path) {
        const txid = entry.tx.id as Txid;
        for (let j = 0; j < entry.tx.inputsLength; j++) {
            const cosigners = getArkPsbtFields(entry.tx, j, CosignerPublicKey);
            if (cosigners.length === 0) continue;
            checked++;

            const keys = cosigners.map((c) => c.key);
            if (keys.some((k) => k.length !== 33)) {
                failures.push(`${txid} input ${j} invalid cosigner key length`);
                continue;
            }

            const treeBlobs = getArkPsbtFields(entry.tx, j, VtxoTaprootTree);
            if (
                treeBlobs.length > 0 &&
                treeBlobs[0].length > MAX_TAPTREE_BLOB_BYTES
            ) {
                failures.push(
                    `${txid} input ${j} VtxoTaprootTree blob too large (${treeBlobs[0].length} bytes)`
                );
                continue;
            }

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
                    for (const leaf of decoded) {
                        try {
                            const ts = decodeTapscript(leaf.script);
                            if (CSVMultisigTapscript.is(ts)) {
                                sweepTimelock = ts.params.timelock;
                                sweepLeavesFound++;
                                break;
                            }
                        } catch {
                            // Not a recognised Ark tapscript.
                        }
                    }
                } catch {
                    failures.push(
                        `${txid} input ${j} VtxoTaprootTree decode failed`
                    );
                    continue;
                }
            }

            if (!merkleRoot) {
                // Real arkd key-path PSBTs carry CosignerPublicKey but
                // not VtxoTaprootTree. Cannot verify without taptree.
                noTree++;
                continue;
            }

            try {
                const { finalKey } = aggregateKeys(keys, true, {
                    taprootTweak: merkleRoot,
                });
                const parentXOnly =
                    entry.perInputPrevouts[j].script.subarray(2);
                if (parentXOnly.length !== 32) {
                    failures.push(`${txid} input ${j} parent output not P2TR`);
                    continue;
                }
                if (bytesEqual(finalKey.subarray(1), parentXOnly)) {
                    matched++;
                } else {
                    failures.push(
                        `${txid} input ${j} aggregated key does not match parent P2TR`
                    );
                }
            } catch (e) {
                failures.push(
                    `${txid} input ${j} key aggregation failed: ${e instanceof Error ? e.message : String(e)}`
                );
                continue;
            }

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
                    } else {
                        failures.push(
                            `${txid} input ${j} sweep timelock (${sweepTimelock.type}:${sweepTimelock.value}) != VtxoTreeExpiry (${expiry.type}:${expiry.value})`
                        );
                    }
                }
            }
        }
    }

    return {
        name: "sig.musig2-aggregate-valid",
        passed: failures.length === 0,
        details:
            checked === 0
                ? "No inputs carry CosignerPublicKey fields"
                : failures.length > 0
                  ? failures.join("; ")
                  : noTree > 0
                    ? `${matched}/${checked} verified; ${noTree} skipped (no VtxoTaprootTree)`
                    : `${matched}/${checked} aggregated key(s) match parent P2TR`,
        durationMs: Date.now() - start,
        evidence: {
            inputs_checked: checked,
            inputs_matched: matched,
            inputs_no_taptree: noTree,
            sweep_leaves_found: sweepLeavesFound,
            expiry_cross_checks: expiryCrossChecks,
            expiry_matched: expiryMatched,
            mismatches: failures,
        },
    };
}

// Re-export types for external consumers via the barrel.
export type { SignaturePathEntry, Prevout, PerInputPrevouts };
