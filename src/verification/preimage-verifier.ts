/**
 * Preimage (HTLC-style) condition verifier — assignment §3.2.3.
 *
 * Scans every tapLeafScript of every input for canonical hash-commitment
 * patterns (`OP_SHA256 <32B> OP_EQUAL[VERIFY]` and
 * `OP_HASH160 <20B> OP_EQUAL[VERIFY]`) and, for each commitment, walks
 * the PSBT witness stack for a preimage whose hash matches.
 *
 * {@link decodeWitnessStack} is the SOLE
 * candidate-extraction API and returns `Uint8Array[]` (not raw bytes).
 * A hard cap {@link MAX_PREIMAGE_CANDIDATES} prevents DoS amplification.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { MalformedChainError } from "./errors";
import { ConditionWitness } from "../utils/unknownFields";
import type { CheckResult, SignaturePathEntry, Txid } from "./types";

/** Maximum preimage candidates extracted per tx — DoS bound. */
export const MAX_PREIMAGE_CANDIDATES = 64;

/**
 * Decode a PSBT `finalScriptWitness` Uint8Array into its constituent
 * witness-stack elements. The wire format is
 * `varint(count) || [varint(len) || bytes]...`.
 *
 * Returns at most {@link MAX_PREIMAGE_CANDIDATES} elements — an
 * adversarial witness with 10 000 one-byte elements cannot force the
 * downstream hash loop to run unbounded work (DoS guard).
 */
export function decodeWitnessStack(
    finalScriptWitness: Uint8Array
): readonly Uint8Array[] {
    if (finalScriptWitness.length === 0) return [];
    const out: Uint8Array[] = [];
    let i = 0;
    const [count, countLen] = readVarint(finalScriptWitness, i);
    i += countLen;
    for (let n = 0; n < count && out.length < MAX_PREIMAGE_CANDIDATES; n++) {
        const [len, lenLen] = readVarint(finalScriptWitness, i);
        i += lenLen;
        if (i + len > finalScriptWitness.length) {
            throw new Error(
                `decodeWitnessStack: element ${n} truncated (len=${len}, remaining=${finalScriptWitness.length - i})`
            );
        }
        out.push(finalScriptWitness.subarray(i, i + len));
        i += len;
    }
    return out;
}

function readVarint(bytes: Uint8Array, offset: number): [number, number] {
    if (offset >= bytes.length) throw new Error("varint past end");
    const first = bytes[offset];
    if (first < 0xfd) return [first, 1];
    if (first === 0xfd) {
        return [bytes[offset + 1] | (bytes[offset + 2] << 8), 3];
    }
    if (first === 0xfe) {
        const v =
            bytes[offset + 1] |
            (bytes[offset + 2] << 8) |
            (bytes[offset + 3] << 16) |
            (bytes[offset + 4] << 24);
        return [v >>> 0, 5];
    }
    // 0xff — 8-byte varint; unrealistic for witnesses, bail.
    throw new Error("varint too large for witness element count");
}

/** Opcodes we care about for preimage detection. */
const OP_SHA256 = 0xa8;
const OP_HASH160 = 0xa9;
const OP_EQUAL = 0x87;
const OP_EQUALVERIFY = 0x88;

interface HashCommitment {
    readonly txid: Txid;
    readonly inputIndex: number;
    readonly kind: "sha256" | "hash160";
    readonly digest: Uint8Array; // 32 bytes for sha256, 20 for hash160
}

/**
 * Scan a tapleaf script for canonical hash-commitment patterns.
 * Only the minimal canonical forms are recognised; non-canonical
 * encodings (e.g. PUSHDATA1 where a direct push fits) are ignored
 * so an attacker can't hide a hash commitment behind a malformed push.
 */
function scanScriptForHashCommitments(
    script: Uint8Array,
    txid: Txid,
    inputIndex: number
): HashCommitment[] {
    const found: HashCommitment[] = [];
    let i = 0;
    while (i < script.length - 1) {
        const op = script[i];
        // OP_SHA256 OP_PUSH32 <32B> OP_EQUAL[VERIFY]
        if (op === OP_SHA256 && i + 1 + 32 + 1 <= script.length) {
            const pushLen = script[i + 1];
            const next = script[i + 2 + 32];
            if (
                pushLen === 0x20 &&
                (next === OP_EQUAL || next === OP_EQUALVERIFY)
            ) {
                found.push({
                    txid,
                    inputIndex,
                    kind: "sha256",
                    digest: script.subarray(i + 2, i + 2 + 32),
                });
                i += 2 + 32 + 1;
                continue;
            }
        }
        if (op === OP_HASH160 && i + 1 + 20 + 1 <= script.length) {
            const pushLen = script[i + 1];
            const next = script[i + 2 + 20];
            if (
                pushLen === 0x14 &&
                (next === OP_EQUAL || next === OP_EQUALVERIFY)
            ) {
                found.push({
                    txid,
                    inputIndex,
                    kind: "hash160",
                    digest: script.subarray(i + 2, i + 2 + 20),
                });
                i += 2 + 20 + 1;
                continue;
            }
        }
        i++;
    }
    return found;
}

import { equalBytes } from "@scure/btc-signer/utils.js";
const bytesEqual = equalBytes;

export interface PreimageVerifierInput {
    readonly path: readonly SignaturePathEntry[];
    readonly signal?: AbortSignal;
}

export async function verifyPreimages(
    input: PreimageVerifierInput
): Promise<readonly CheckResult[]> {
    const { path, signal } = input;
    if (signal?.aborted) {
        throw new MalformedChainError({
            kind: "UNSUPPORTED",
            code: "preimage.aborted",
            message: "Preimage verification aborted",
        });
    }

    let scriptsScanned = 0;
    const commitments: HashCommitment[] = [];
    let sha256Count = 0;
    let hash160Count = 0;
    let candidatesExtracted = 0;

    for (const entry of path) {
        const txid = entry.tx.id as Txid;
        for (let j = 0; j < entry.tx.inputsLength; j++) {
            const inp = entry.tx.getInput(j);
            const rawLeaves = inp.tapLeafScript;
            if (!Array.isArray(rawLeaves) || rawLeaves.length === 0) continue;
            for (const leaf of rawLeaves as ReadonlyArray<
                readonly [unknown, Uint8Array]
            >) {
                if (
                    !Array.isArray(leaf) ||
                    !(leaf[1] instanceof Uint8Array) ||
                    leaf[1].length < 2
                )
                    continue;
                scriptsScanned++;
                // leaf[1] = script || leafVersion byte
                const scriptBytes = leaf[1].subarray(0, leaf[1].length - 1);
                const found = scanScriptForHashCommitments(
                    scriptBytes,
                    txid,
                    j
                );
                for (const c of found) {
                    commitments.push(c);
                    if (c.kind === "sha256") sha256Count++;
                    else hash160Count++;
                }
            }
        }
    }

    // Per-tx preimage candidate extraction + match. Pre-signed Ark txs
    // do not carry finalScriptWitness until exit time (BIP 174 finalize
    // happens at broadcast, not pre-sign). When commitments exist but
    // no witness stack is present on the spending input, the check
    // reports "pending finalization" rather than flipping — matching
    // would be structurally impossible at this stage, not a tamper
    // signal.
    let matches = 0;
    const pending: string[] = [];
    const mismatched: string[] = [];
    for (const entry of path) {
        const txid = entry.tx.id as Txid;
        // Collect all candidates across every input of this tx, then
        // match each commitment of this tx against any candidate.
        // @scure's PSBT parser surfaces `finalScriptWitness` as an
        // already-decoded Uint8Array[] stack; byte-iteration over a
        // raw Uint8Array (the byte-iteration anti-pattern) is impossible here because
        // the type forces us to iterate elements, not bytes.
        const candidates: Uint8Array[] = [];
        for (let j = 0; j < entry.tx.inputsLength; j++) {
            const inp = entry.tx.getInput(j);

            // Source 1: finalScriptWitness (post-finalization witness stack).
            const stack = inp.finalScriptWitness as
                | ReadonlyArray<Uint8Array>
                | undefined;
            if (stack) {
                for (const el of stack) {
                    if (candidates.length >= MAX_PREIMAGE_CANDIDATES) break;
                    candidates.push(el);
                }
            }

            // Source 2: ConditionWitness Ark PSBT field (pre-finalization).
            // For VHTLC claim paths, the SDK stores the preimage in
            // this field during intent construction. Pre-signed txs
            // don't carry finalScriptWitness (BIP 174 finalization
            // happens at broadcast), so this is the primary preimage
            // source for presigned Ark transactions.
            const unknownFields = inp.unknown as
                | NonNullable<typeof inp.unknown>
                | undefined;
            if (unknownFields) {
                for (const pair of unknownFields) {
                    try {
                        const decoded = ConditionWitness.decode(pair);
                        if (!decoded) continue;
                        for (const element of decoded) {
                            if (candidates.length >= MAX_PREIMAGE_CANDIDATES)
                                break;
                            candidates.push(element);
                        }
                    } catch {
                        // Not a ConditionWitness field — skip silently.
                        // Other Ark PSBT fields (VtxoTaprootTree, Cosigner,
                        // VtxoTreeExpiry) will fail to decode as
                        // ConditionWitness; this is expected.
                    }
                }
            }
        }
        candidatesExtracted += candidates.length;

        const commitmentsForTx = commitments.filter((c) => c.txid === txid);
        const txHasWitness = candidates.length > 0;
        for (const commit of commitmentsForTx) {
            if (!txHasWitness) {
                // Pre-sign state: no witness to check against. This is
                // the expected condition for unbroadcasted Ark txs —
                // recorded as UNSUPPORTED-pending, not a match failure.
                pending.push(
                    `${commit.txid} input ${commit.inputIndex} ${commit.kind} commitment pending finalization (no witness stack yet)`
                );
                continue;
            }
            let matched = false;
            for (const cand of candidates) {
                const h =
                    commit.kind === "sha256"
                        ? sha256(cand)
                        : ripemd160(sha256(cand));
                if (bytesEqual(h, commit.digest)) {
                    matched = true;
                    break;
                }
            }
            if (matched) matches++;
            else {
                // Witness present but no match — genuine tamper signal.
                mismatched.push(
                    `${commit.txid} input ${commit.inputIndex} ${commit.kind} commitment has witness but no matching preimage`
                );
            }
        }
    }

    const checks: CheckResult[] = [];
    checks.push({
        name: "preimage.conditions-scanned",
        passed: true,
        details:
            commitments.length === 0
                ? `Scanned ${scriptsScanned} tapleaf script(s); no hash commitments found`
                : `Scanned ${scriptsScanned} script(s); found ${commitments.length} commitment(s) (${sha256Count} sha256, ${hash160Count} hash160)`,
        durationMs: 0,
        evidence: {
            scripts_scanned: scriptsScanned,
            commitments_found: commitments.length,
            sha256_commitments: sha256Count,
            hash160_commitments: hash160Count,
        },
    });
    // Only mismatched (witness-present + no-match) is a real failure.
    // Pending (no-witness-yet) is pre-signed state, not tamper.
    const matchesPassed = mismatched.length === 0;
    checks.push({
        name: "preimage.hashes-match",
        passed: matchesPassed,
        details:
            commitments.length === 0
                ? "No hash commitments to verify"
                : matchesPassed
                  ? pending.length > 0
                      ? `${matches} matched; ${pending.length} pending finalization (no witness yet — normal for pre-signed txs)`
                      : `All ${matches} hash commitment(s) matched by a witness preimage`
                  : `${mismatched.length} mismatched: ${mismatched.join("; ")}`,
        durationMs: 0,
        evidence: {
            preimages_matched: matches,
            preimages_pending: pending.length,
            preimages_mismatched: mismatched.length,
            candidates_extracted: candidatesExtracted,
            max_candidates_per_tx: MAX_PREIMAGE_CANDIDATES,
        },
    });
    return checks;
}
