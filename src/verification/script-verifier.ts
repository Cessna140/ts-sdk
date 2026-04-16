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
 *     input (via DagAdapter, B3 invariant), the internal key MUST be
 *     BIP 341's NUMS point. v1 checked only the topmost entry; v2
 *     iterates every such input.
 *   - `script.vtxotaprootree-valid`: if the input carries a
 *     `VtxoTaprootTree` PSBT unknown field, decode it and assert the
 *     executed tapleaf is a leaf of the declared tree.
 *
 * Unrecognised Ark-namespaced PSBT unknown fields emit an `UNSUPPORTED`
 * row in `errors[]` rather than silently passing.
 */

import { sha256 } from "@noble/hashes/sha2.js";
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

/** TapBranch tagged hash: sha256(tag) || sha256(tag) || min(a,b) || max(a,b). */
const TAP_BRANCH_TAG = sha256(new TextEncoder().encode("TapBranch"));
function tapBranchHash(a: Uint8Array, b: Uint8Array): Uint8Array {
    const [lo, hi] = compareBytes(a, b) <= 0 ? [a, b] : [b, a];
    const buf = new Uint8Array(
        TAP_BRANCH_TAG.length * 2 + lo.length + hi.length
    );
    buf.set(TAP_BRANCH_TAG, 0);
    buf.set(TAP_BRANCH_TAG, TAP_BRANCH_TAG.length);
    buf.set(lo, TAP_BRANCH_TAG.length * 2);
    buf.set(hi, TAP_BRANCH_TAG.length * 2 + lo.length);
    return sha256(buf);
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i++) {
        if (a[i] !== b[i]) return a[i] - b[i];
    }
    return a.length - b.length;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

function p2trXOnlyKey(script: Uint8Array): Uint8Array | null {
    if (script.length !== 34 || script[0] !== 0x51 || script[1] !== 0x20) {
        return null;
    }
    return script.subarray(2);
}

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
    if (signal?.aborted) {
        throw new MalformedChainError({
            kind: "UNSUPPORTED",
            code: "script.aborted",
            message: "Script verification aborted",
        });
    }

    const checks: CheckResult[] = [];
    const errors: VerificationError[] = [];

    let controlBlocksChecked = 0;
    let controlBlocksFailed = 0;
    const controlBlockDetails: string[] = [];
    let merkleChecked = 0;
    let merkleMatched = 0;
    const merkleDetails: string[] = [];
    let vtreeChecked = 0;
    let vtreeMatched = 0;
    const vtreeDetails: string[] = [];

    for (const entry of path) {
        const txid = entry.tx.id as Txid;
        collectUnknownArkFieldErrors(entry.tx, txid, errors);

        for (let j = 0; j < entry.tx.inputsLength; j++) {
            const inp = entry.tx.getInput(j);
            const tapLeafField = inp.tapLeafScript as
                | ReadonlyArray<
                      readonly [
                          {
                              version: number;
                              internalKey: Uint8Array;
                              merklePath: Uint8Array[];
                          },
                          Uint8Array,
                      ]
                  >
                | undefined;
            if (!tapLeafField || tapLeafField.length === 0) continue;

            const parentScript = entry.perInputPrevouts[j].script;
            const parentKey = p2trXOnlyKey(parentScript);
            if (!parentKey) {
                throw new MalformedChainError({
                    kind: "DATA",
                    code: "script.parent-not-p2tr",
                    message: `Tx ${txid} input ${j} parent is not P2TR`,
                    context: { txid, input_index: j },
                });
            }

            for (let k = 0; k < tapLeafField.length; k++) {
                const [ctrl, scriptBytes] = tapLeafField[k];
                controlBlocksChecked++;

                // 1. Control-block length validation
                if (
                    !(ctrl.internalKey instanceof Uint8Array) ||
                    ctrl.internalKey.length !== 32
                ) {
                    controlBlocksFailed++;
                    controlBlockDetails.push(
                        `${txid} input ${j} leaf[${k}] internalKey is not 32 bytes`
                    );
                    continue;
                }
                for (const step of ctrl.merklePath) {
                    if (!(step instanceof Uint8Array) || step.length !== 32) {
                        controlBlocksFailed++;
                        controlBlockDetails.push(
                            `${txid} input ${j} leaf[${k}] merkle step is not 32 bytes`
                        );
                        break;
                    }
                }
                // Per BIP 341 the control-block first byte packs leaf
                // version in the high bits + parity in bit 0; @scure
                // exposes this packed value as ctrl.version. 0xc0 and
                // 0xc1 are both valid tapscript leaves; mask the
                // parity bit before comparing.
                if ((ctrl.version & 0xfe) !== LEAF_VERSION_TAPSCRIPT) {
                    throw new UnsupportedFeatureError({
                        kind: "UNSUPPORTED",
                        code: "script.unsupported-leaf-version",
                        message: `Tx ${txid} input ${j} leaf[${k}] has leaf version 0x${ctrl.version.toString(16)} (only 0xc0/0xc1 tapscript supported)`,
                        context: {
                            txid,
                            input_index: j,
                            leaf_version: ctrl.version,
                        },
                    });
                }

                // 2. Compute tapleaf hash from `scriptBytes` (which
                // carries `script || leafVersion`).
                const script = scriptBytes.subarray(0, scriptBytes.length - 1);
                // tapLeafHash takes the bare leaf version (parity bit
                // masked off) per BIP 341.
                const leafHash = tapLeafHash(script, ctrl.version & 0xfe);

                // 3. Walk merkle path to the root
                let node = leafHash;
                for (const step of ctrl.merklePath) {
                    node = tapBranchHash(node, step);
                }

                // 4. Tweak the internal key by the computed root
                const [tweaked] = taprootTweakPubkey(ctrl.internalKey, node);

                merkleChecked++;
                if (bytesEqual(tweaked, parentKey)) {
                    merkleMatched++;
                } else {
                    merkleDetails.push(
                        `${txid} input ${j} leaf[${k}] tweaked key != parent P2TR`
                    );
                }

                // 5. VtxoTaprootTree containment check — if the PSBT
                // carries the field, assert this leafHash is a leaf
                // of the declared tree.
                const vtreeBlob = extractVtxoTaprootTreeBlob(entry.tx, j);
                if (vtreeBlob !== null) {
                    vtreeChecked++;
                    const declared = decodeVtxoTaprootTree(vtreeBlob);
                    if (declared === null) {
                        errors.push({
                            kind: "DATA",
                            code: "script.vtxotaprootree-decode",
                            message: `Tx ${txid} input ${j} VtxoTaprootTree field is malformed`,
                            context: { txid, input_index: j },
                        });
                    } else {
                        const contained = declared.some((h) =>
                            bytesEqual(h, leafHash)
                        );
                        if (contained) vtreeMatched++;
                        else {
                            vtreeDetails.push(
                                `${txid} input ${j} leaf[${k}] not a leaf of declared VtxoTaprootTree`
                            );
                        }
                    }
                }
            }
        }
    }

    // NUMS check (§3.1.2 §3.2.1, B3 invariant) — every
    // COMMITMENT-parented input must have the NUMS internal key on its
    // topmost tapLeafScript control block. Iteration via DagAdapter,
    // not path[length-1].
    let numsChecked = 0;
    let numsMatched = 0;
    const numsDetails: string[] = [];
    if (dag) {
        const byTxid = new Map<Txid, SignaturePathEntry>();
        for (const e of path) byTxid.set(e.tx.id as Txid, e);
        for (const edge of dag.commitmentParentedInputs()) {
            const entry = byTxid.get(edge.childTxid);
            if (!entry) continue;
            const inp = entry.tx.getInput(edge.inputIndex);
            const tapLeafField = inp.tapLeafScript as
                | ReadonlyArray<
                      readonly [{ internalKey: Uint8Array }, Uint8Array]
                  >
                | undefined;
            if (!tapLeafField || tapLeafField.length === 0) {
                // Key-path commitment input has no tapleaf; NUMS is
                // enforced implicitly by the MuSig2 aggregate tweak —
                // skip here (exercised by sig.musig2-aggregate-valid).
                continue;
            }
            numsChecked++;
            const internalKey = tapLeafField[0][0].internalKey;
            if (bytesEqual(internalKey, TAPROOT_UNSPENDABLE_KEY)) {
                numsMatched++;
            } else {
                numsDetails.push(
                    `${edge.childTxid} input ${edge.inputIndex} parent is COMMITMENT but internal key != NUMS`
                );
            }
        }
    }

    checks.push({
        name: "script.control-block-valid",
        passed: controlBlocksFailed === 0,
        details:
            controlBlocksFailed === 0
                ? `${controlBlocksChecked} control block(s) well-formed`
                : controlBlockDetails.join("; "),
        durationMs: 0,
        evidence: {
            control_blocks_checked: controlBlocksChecked,
            control_blocks_failed: controlBlocksFailed,
        },
    });
    checks.push({
        name: "script.merkle-root-matches",
        passed: merkleChecked === merkleMatched,
        details:
            merkleChecked === merkleMatched
                ? `${merkleMatched}/${merkleChecked} tweaked-key reconstructions match parent P2TR`
                : merkleDetails.join("; "),
        durationMs: 0,
        evidence: {
            merkle_checks: merkleChecked,
            merkle_matched: merkleMatched,
        },
    });
    checks.push({
        name: "script.internal-key-is-nums",
        passed: numsChecked === numsMatched,
        details:
            numsChecked === 0
                ? "No script-path COMMITMENT-parented inputs (key-path spends use MuSig2; see sig.musig2-aggregate-valid)"
                : numsChecked === numsMatched
                  ? `${numsMatched}/${numsChecked} COMMITMENT-parented input(s) use NUMS internal key`
                  : numsDetails.join("; "),
        durationMs: 0,
        evidence: {
            inputs_checked: numsChecked,
            inputs_matched: numsMatched,
            nums_expected_hex: Array.from(TAPROOT_UNSPENDABLE_KEY)
                .map((b) => b.toString(16).padStart(2, "0"))
                .join(""),
        },
    });
    checks.push({
        name: "script.vtxotaprootree-valid",
        passed: vtreeChecked === vtreeMatched,
        details:
            vtreeChecked === 0
                ? "No inputs carry a VtxoTaprootTree field (trivially valid)"
                : vtreeChecked === vtreeMatched
                  ? `${vtreeMatched}/${vtreeChecked} executed tapleaves are declared-tree members`
                  : vtreeDetails.join("; "),
        durationMs: 0,
        evidence: {
            vtxotree_checks: vtreeChecked,
            vtxotree_matched: vtreeMatched,
        },
    });

    return { checks, errors };
}
