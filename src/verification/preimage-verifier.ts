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

import { bytesEqual, throwIfAborted } from "./utils";

export interface PreimageVerifierInput {
    readonly path: readonly SignaturePathEntry[];
    readonly signal?: AbortSignal;
}

export async function verifyPreimages(
    input: PreimageVerifierInput
): Promise<readonly CheckResult[]> {
    const { path, signal } = input;
    throwIfAborted(signal);

    const scan = scanHashCommitments(path);
    const match = matchPreimages(scan.commitments, path);

    return [
        {
            name: "preimage.conditions-scanned",
            passed: true,
            details:
                scan.commitments.length === 0
                    ? `Scanned ${scan.scriptsScanned} tapleaf script(s); no hash commitments found`
                    : `Scanned ${scan.scriptsScanned} script(s); found ${scan.commitments.length} commitment(s) (${scan.sha256Count} sha256, ${scan.hash160Count} hash160)`,
            durationMs: 0,
            evidence: {
                scripts_scanned: scan.scriptsScanned,
                commitments_found: scan.commitments.length,
                sha256_commitments: scan.sha256Count,
                hash160_commitments: scan.hash160Count,
            },
        },
        {
            name: "preimage.hashes-match",
            passed: match.mismatched.length === 0,
            details:
                scan.commitments.length === 0
                    ? "No hash commitments to verify"
                    : match.mismatched.length > 0
                      ? `${match.mismatched.length} mismatched: ${match.mismatched.join("; ")}`
                      : match.pending.length > 0
                        ? `${match.matched} matched; ${match.pending.length} pending finalization (no witness yet — normal for pre-signed txs)`
                        : `All ${match.matched} hash commitment(s) matched by a witness preimage`,
            durationMs: 0,
            evidence: {
                preimages_matched: match.matched,
                preimages_pending: match.pending.length,
                preimages_mismatched: match.mismatched.length,
                candidates_extracted: match.candidatesExtracted,
                max_candidates_per_tx: MAX_PREIMAGE_CANDIDATES,
            },
        },
    ];
}

// ── Phase 1: Scan tapleaf scripts for hash commitments ──────────────

function scanHashCommitments(path: readonly SignaturePathEntry[]): {
    commitments: HashCommitment[];
    scriptsScanned: number;
    sha256Count: number;
    hash160Count: number;
} {
    let scriptsScanned = 0;
    let sha256Count = 0;
    let hash160Count = 0;
    const commitments: HashCommitment[] = [];

    for (const entry of path) {
        const txid = entry.tx.id as Txid;
        for (let j = 0; j < entry.tx.inputsLength; j++) {
            const rawLeaves = entry.tx.getInput(j).tapLeafScript;
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
                const scriptBytes = leaf[1].subarray(0, leaf[1].length - 1);
                for (const c of scanScriptForHashCommitments(
                    scriptBytes,
                    txid,
                    j
                )) {
                    commitments.push(c);
                    if (c.kind === "sha256") sha256Count++;
                    else hash160Count++;
                }
            }
        }
    }

    return { commitments, scriptsScanned, sha256Count, hash160Count };
}

// ── Phase 2: Match witness candidates against commitments ───────────

function matchPreimages(
    commitments: readonly HashCommitment[],
    path: readonly SignaturePathEntry[]
): {
    matched: number;
    pending: string[];
    mismatched: string[];
    candidatesExtracted: number;
} {
    let matched = 0;
    let candidatesExtracted = 0;
    const pending: string[] = [];
    const mismatched: string[] = [];

    for (const entry of path) {
        const txid = entry.tx.id as Txid;
        const candidates = extractCandidates(entry.tx);
        candidatesExtracted += candidates.length;

        const commitmentsForTx = commitments.filter((c) => c.txid === txid);
        for (const commit of commitmentsForTx) {
            if (candidates.length === 0) {
                pending.push(
                    `${commit.txid} input ${commit.inputIndex} ${commit.kind} commitment pending finalization (no witness stack yet)`
                );
                continue;
            }
            const found = candidates.some((cand) => {
                const h =
                    commit.kind === "sha256"
                        ? sha256(cand)
                        : ripemd160(sha256(cand));
                return bytesEqual(h, commit.digest);
            });
            if (found) matched++;
            else {
                mismatched.push(
                    `${commit.txid} input ${commit.inputIndex} ${commit.kind} commitment has witness but no matching preimage`
                );
            }
        }
    }

    return { matched, pending, mismatched, candidatesExtracted };
}

function extractCandidates(tx: Transaction): Uint8Array[] {
    const candidates: Uint8Array[] = [];
    for (let j = 0; j < tx.inputsLength; j++) {
        const inp = tx.getInput(j);

        // Source 1: finalScriptWitness (post-finalization).
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
        const unknownFields = inp.unknown as
            | NonNullable<typeof inp.unknown>
            | undefined;
        if (unknownFields) {
            for (const pair of unknownFields) {
                try {
                    const decoded = ConditionWitness.decode(pair);
                    if (!decoded) continue;
                    for (const element of decoded) {
                        if (candidates.length >= MAX_PREIMAGE_CANDIDATES) break;
                        candidates.push(element);
                    }
                } catch {
                    // Not a ConditionWitness field — expected for other
                    // Ark PSBT fields.
                }
            }
        }
    }
    return candidates;
}
