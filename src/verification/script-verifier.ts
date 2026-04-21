/**
 * Script-tree verifier — assignment §3.2.1.
 *
 * For each input's script-path witness:
 *   1. Parse the control block: 1B leaf-version/parity || 32B internal
 *      key || N × 32B merkle-path entries.
 *   2. Compute the tapleaf hash from the spent script + leaf version.
 *   3. Walk the merkle path with TapBranch tagged hashes.
 *   4. Tweak the internal key by the reconstructed merkle root.
 *   5. Assert the tweaked x-only key equals the parent P2TR output.
 *
 * Additional §3.2.1 + v2 checks:
 *   - `script.internal-key-is-nums`: for every COMMITMENT-parented
 *     input (via DagAdapter iterator), the internal key MUST be
 *     BIP 341's NUMS point.
 *   - `script.vtxotaprootree-valid`: if the input carries a
 *     `VtxoTaprootTree` PSBT unknown field, decode it and assert the
 *     executed tapleaf is a leaf of the declared tree.
 *
 * Unrecognised Ark-namespaced PSBT unknown fields emit an `UNSUPPORTED`
 * row in `errors[]` rather than silently passing.
 */

import { Transaction } from "@scure/btc-signer/transaction.js";
import { tapLeafHash } from "@scure/btc-signer/payment.js";
import { TapTreeCoder } from "../script/base";
import {
    TAPROOT_UNSPENDABLE_KEY,
    taprootTweakPubkey,
} from "@scure/btc-signer/utils.js";
import { MalformedChainError, UnsupportedFeatureError } from "./errors";
import type {
    CheckResult,
    SignaturePathEntry,
    Txid,
    VerificationError,
} from "./types";
import type { DagAdapter } from "./chain-walker";
import {
    bytesEqual,
    tapBranchHash,
    p2trXOnlyKey,
    throwIfAborted,
    MAX_TAPTREE_BLOB_BYTES,
} from "./utils";

export interface ScriptVerifierInput {
    readonly path: readonly SignaturePathEntry[];
    readonly dag?: DagAdapter;
    readonly signal?: AbortSignal;
}

export interface ScriptVerifierOutput {
    readonly checks: readonly CheckResult[];
    readonly errors: readonly VerificationError[];
}

const LEAF_VERSION_TAPSCRIPT = 0xc0;

/**
 * Ark protocol PSBT field key-type byte. Every Ark-namespaced
 * unknown field uses this type (see `src/utils/unknownFields.ts`
 * `ArkPsbtFieldKeyType`). The discriminator is the `key` bytes (UTF-8
 * keyword), not the type byte.
 */
const ARK_PSBT_FIELD_KEY_TYPE = 222;

/**
 * Recognised Ark-namespaced key-bytes prefixes. Unknown fields with
 * `type === 222` whose `key` starts with any of these are known Ark
 * fields; anything else with type 222 emits an `ark.unknown-field`
 * UNSUPPORTED row so future protocol additions surface in the trace
 * rather than being silently ignored. Encoded via UTF-8 per
 * `encodedPsbtFieldKey` in `unknownFields.ts`.
 */
const KNOWN_ARK_KEY_PREFIXES: readonly string[] = [
    "taptree", // VtxoTaprootTree
    "expiry", // VtxoTreeExpiry
    "cosigner", // CosignerPublicKey (cosigner + 1-byte index)
    "condition", // ConditionWitness
];

function keyStartsWith(keyBytes: Uint8Array, prefix: string): boolean {
    if (keyBytes.length < prefix.length) return false;
    for (let i = 0; i < prefix.length; i++) {
        if (keyBytes[i] !== prefix.charCodeAt(i)) return false;
    }
    return true;
}

/**
 * Decode the `VtxoTaprootTree` PSBT unknown field via the SDK's
 * `TapTreeCoder` (BIP 371 PSBT_OUT_TAP_TREE format:
 * array of `{depth: U8, version: U8, script: VarBytes}`). Returns the
 * leaf-hash array for merkle-containment checks.
 */
function decodeVtxoTaprootTree(blob: Uint8Array): readonly Uint8Array[] | null {
    if (blob.length === 0) return [];
    if (blob.length > MAX_TAPTREE_BLOB_BYTES) return null;
    try {
        const decoded = TapTreeCoder.decode(blob) as ReadonlyArray<{
            depth: number;
            version: number;
            script: Uint8Array;
        }>;
        return decoded.map((leaf) => tapLeafHash(leaf.script, leaf.version));
    } catch {
        return null;
    }
}

function collectUnknownArkFieldErrors(
    tx: Transaction,
    txid: Txid,
    errors: VerificationError[]
): void {
    for (let j = 0; j < tx.inputsLength; j++) {
        const inp = tx.getInput(j);
        const unknownMap = (inp as { unknown?: unknown }).unknown;
        if (!unknownMap) continue;
        const entries: Array<[{ type: number; key: Uint8Array }, Uint8Array]> =
            Array.isArray(unknownMap)
                ? (unknownMap as Array<
                      [{ type: number; key: Uint8Array }, Uint8Array]
                  >)
                : [];
        for (const [keyDescriptor] of entries) {
            if (
                !keyDescriptor ||
                keyDescriptor.type !== ARK_PSBT_FIELD_KEY_TYPE ||
                !(keyDescriptor.key instanceof Uint8Array)
            )
                continue;
            const matches = KNOWN_ARK_KEY_PREFIXES.some((p) =>
                keyStartsWith(keyDescriptor.key, p)
            );
            if (!matches) {
                const keyPreview = Array.from(keyDescriptor.key.slice(0, 16))
                    .map((b) => b.toString(16).padStart(2, "0"))
                    .join("");
                errors.push({
                    kind: "UNSUPPORTED",
                    code: "ark.unknown-field",
                    message: `Tx ${txid} input ${j} carries unrecognised Ark PSBT field key 0x${keyPreview}`,
                    context: {
                        txid,
                        input_index: j,
                        key_prefix_hex: keyPreview,
                    },
                });
            }
        }
    }
}

function extractVtxoTaprootTreeBlob(
    tx: Transaction,
    j: number
): Uint8Array | null {
    const inp = tx.getInput(j);
    const unknownMap = (inp as { unknown?: unknown }).unknown;
    if (!Array.isArray(unknownMap)) return null;
    for (const pair of unknownMap as Array<
        [{ type: number; key: Uint8Array }, Uint8Array]
    >) {
        const keyDescriptor = pair[0];
        const blob = pair[1];
        if (
            keyDescriptor?.type === ARK_PSBT_FIELD_KEY_TYPE &&
            keyDescriptor.key instanceof Uint8Array &&
            keyStartsWith(keyDescriptor.key, "taptree") &&
            blob instanceof Uint8Array
        ) {
            return blob;
        }
    }
    return null;
}

export async function verifyScripts(
    input: ScriptVerifierInput
): Promise<ScriptVerifierOutput> {
    const { path, dag, signal } = input;
    throwIfAborted(signal);

    const errors: VerificationError[] = [];
    for (const entry of path) {
        collectUnknownArkFieldErrors(entry.tx, entry.tx.id as Txid, errors);
    }

    const { controlBlock, merkle, vtree } = checkTapLeafScripts(path, errors);
    const nums = checkNumsInternalKey(path, dag);

    return {
        checks: [controlBlock, merkle, nums, vtree],
        errors,
    };
}

// ── Tap-leaf script checks ──────────────────────────────────────────

function checkTapLeafScripts(
    path: readonly SignaturePathEntry[],
    errors: VerificationError[]
): {
    controlBlock: CheckResult;
    merkle: CheckResult;
    vtree: CheckResult;
} {
    const cb = { checked: 0, failed: 0, details: [] as string[] };
    const mk = { checked: 0, matched: 0, details: [] as string[] };
    const vt = { checked: 0, matched: 0, details: [] as string[] };

    for (const entry of path) {
        const txid = entry.tx.id as Txid;
        for (let j = 0; j < entry.tx.inputsLength; j++) {
            const tapLeafField = parseTapLeafField(entry.tx.getInput(j));
            if (!tapLeafField) continue;

            const parentKey = p2trXOnlyKey(entry.perInputPrevouts[j].script);
            if (!parentKey) {
                throw new MalformedChainError({
                    kind: "DATA",
                    code: "script.parent-not-p2tr",
                    message: `Tx ${txid} input ${j} parent is not P2TR`,
                    context: { txid, input_index: j },
                });
            }

            for (let k = 0; k < tapLeafField.length; k++) {
                const leafHash = validateControlBlock(
                    cb,
                    tapLeafField[k],
                    txid,
                    j,
                    k
                );
                if (!leafHash) continue;

                verifyMerkleRoot(
                    mk,
                    leafHash,
                    tapLeafField[k],
                    parentKey,
                    txid,
                    j,
                    k
                );
                verifyVtxoTreeContainment(
                    vt,
                    leafHash,
                    entry.tx,
                    j,
                    txid,
                    k,
                    errors
                );
            }
        }
    }

    return {
        controlBlock: {
            name: "script.control-block-valid",
            passed: cb.failed === 0,
            details:
                cb.failed === 0
                    ? `${cb.checked} control block(s) well-formed`
                    : cb.details.join("; "),
            durationMs: 0,
            evidence: {
                control_blocks_checked: cb.checked,
                control_blocks_failed: cb.failed,
            },
        },
        merkle: {
            name: "script.merkle-root-matches",
            passed: mk.checked === mk.matched,
            details:
                mk.checked === mk.matched
                    ? `${mk.matched}/${mk.checked} tweaked-key reconstructions match parent P2TR`
                    : mk.details.join("; "),
            durationMs: 0,
            evidence: {
                merkle_checks: mk.checked,
                merkle_matched: mk.matched,
            },
        },
        vtree: {
            name: "script.vtxotaprootree-valid",
            passed: vt.checked === vt.matched,
            details:
                vt.checked === 0
                    ? "No inputs carry a VtxoTaprootTree field (trivially valid)"
                    : vt.checked === vt.matched
                      ? `${vt.matched}/${vt.checked} executed tapleaves are declared-tree members`
                      : vt.details.join("; "),
            durationMs: 0,
            evidence: {
                vtxotree_checks: vt.checked,
                vtxotree_matched: vt.matched,
            },
        },
    };
}

type TapLeafEntry = readonly [
    {
        version: number;
        internalKey: Uint8Array;
        merklePath: Uint8Array[];
    },
    Uint8Array,
];

function parseTapLeafField(
    inp: ReturnType<Transaction["getInput"]>
): ReadonlyArray<TapLeafEntry> | null {
    const raw = inp.tapLeafScript;
    if (!Array.isArray(raw) || raw.length === 0) return null;
    const sample = raw[0];
    if (
        !Array.isArray(sample) ||
        sample.length < 2 ||
        typeof sample[0]?.version !== "number" ||
        !(sample[0]?.internalKey instanceof Uint8Array) ||
        !(sample[1] instanceof Uint8Array)
    )
        return null;
    return raw as ReadonlyArray<TapLeafEntry>;
}

function validateControlBlock(
    cb: { checked: number; failed: number; details: string[] },
    leaf: TapLeafEntry,
    txid: Txid,
    j: number,
    k: number
): Uint8Array | null {
    const [ctrl, scriptBytes] = leaf;
    cb.checked++;

    if (
        !(ctrl.internalKey instanceof Uint8Array) ||
        ctrl.internalKey.length !== 32
    ) {
        cb.failed++;
        cb.details.push(
            `${txid} input ${j} leaf[${k}] internalKey is not 32 bytes`
        );
        return null;
    }
    for (const step of ctrl.merklePath) {
        if (!(step instanceof Uint8Array) || step.length !== 32) {
            cb.failed++;
            cb.details.push(
                `${txid} input ${j} leaf[${k}] merkle step is not 32 bytes`
            );
            return null;
        }
    }
    if ((ctrl.version & 0xfe) !== LEAF_VERSION_TAPSCRIPT) {
        throw new UnsupportedFeatureError({
            kind: "UNSUPPORTED",
            code: "script.unsupported-leaf-version",
            message: `Tx ${txid} input ${j} leaf[${k}] has leaf version 0x${ctrl.version.toString(16)}`,
            context: { txid, input_index: j, leaf_version: ctrl.version },
        });
    }

    const script = scriptBytes.subarray(0, scriptBytes.length - 1);
    return tapLeafHash(script, ctrl.version & 0xfe);
}

function verifyMerkleRoot(
    mk: { checked: number; matched: number; details: string[] },
    leafHash: Uint8Array,
    leaf: TapLeafEntry,
    parentKey: Uint8Array,
    txid: Txid,
    j: number,
    k: number
): void {
    const [ctrl] = leaf;
    let node = leafHash;
    for (const step of ctrl.merklePath) {
        node = tapBranchHash(node, step);
    }
    const [tweaked] = taprootTweakPubkey(ctrl.internalKey, node);
    mk.checked++;
    if (bytesEqual(tweaked, parentKey)) {
        mk.matched++;
    } else {
        mk.details.push(
            `${txid} input ${j} leaf[${k}] tweaked key != parent P2TR`
        );
    }
}

function verifyVtxoTreeContainment(
    vt: { checked: number; matched: number; details: string[] },
    leafHash: Uint8Array,
    tx: Transaction,
    j: number,
    txid: Txid,
    k: number,
    errors: VerificationError[]
): void {
    const vtreeBlob = extractVtxoTaprootTreeBlob(tx, j);
    if (vtreeBlob === null) return;
    vt.checked++;
    const declared = decodeVtxoTaprootTree(vtreeBlob);
    if (declared === null) {
        errors.push({
            kind: "DATA",
            code: "script.vtxotaprootree-decode",
            message: `Tx ${txid} input ${j} VtxoTaprootTree field is malformed`,
            context: { txid, input_index: j },
        });
    } else if (declared.some((h) => bytesEqual(h, leafHash))) {
        vt.matched++;
    } else {
        vt.details.push(
            `${txid} input ${j} leaf[${k}] not a leaf of declared VtxoTaprootTree`
        );
    }
}

// ── NUMS internal-key check ─────────────────────────────────────────

function checkNumsInternalKey(
    path: readonly SignaturePathEntry[],
    dag?: DagAdapter
): CheckResult {
    let checked = 0;
    let matched = 0;
    const details: string[] = [];

    if (dag) {
        const byTxid = new Map<Txid, SignaturePathEntry>();
        for (const e of path) byTxid.set(e.tx.id as Txid, e);
        for (const edge of dag.commitmentParentedInputs()) {
            const entry = byTxid.get(edge.childTxid);
            if (!entry) continue;
            const inp = entry.tx.getInput(edge.inputIndex);
            const rawTapLeaf = inp.tapLeafScript;
            if (!Array.isArray(rawTapLeaf) || rawTapLeaf.length === 0) continue;
            const first = rawTapLeaf[0];
            if (
                !Array.isArray(first) ||
                !(first[0]?.internalKey instanceof Uint8Array)
            )
                continue;
            checked++;
            if (bytesEqual(first[0].internalKey, TAPROOT_UNSPENDABLE_KEY)) {
                matched++;
            } else {
                details.push(
                    `${edge.childTxid} input ${edge.inputIndex} parent is COMMITMENT but internal key != NUMS`
                );
            }
        }
    }

    return {
        name: "script.internal-key-is-nums",
        passed: checked === matched,
        details:
            checked === 0
                ? "No script-path COMMITMENT-parented inputs (key-path spends use MuSig2; see sig.musig2-aggregate-valid)"
                : checked === matched
                  ? `${matched}/${checked} COMMITMENT-parented input(s) use NUMS internal key`
                  : details.join("; "),
        durationMs: 0,
        evidence: {
            inputs_checked: checked,
            inputs_matched: matched,
            nums_expected_hex: Array.from(TAPROOT_UNSPENDABLE_KEY)
                .map((b) => b.toString(16).padStart(2, "0"))
                .join(""),
        },
    };
}
