import type { Transaction } from "@scure/btc-signer";

/**
 * Branded display-order txid string (B2 invariant). A txid in Bitcoin has
 * two byte orderings:
 *
 *   - **internal** — the bytes as serialised in the wire format (tx
 *     previous-output reference, CTransaction.id internal field).
 *   - **display** — the reverse of internal. What block explorers,
 *     `bitcoin-cli` output, and `Transaction.id` (getter on @scure's
 *     `Transaction`) produce.
 *
 * Everything in this module uses display order. The three constructors
 * below differ only in what their input's byte order is — each docstring
 * anchors the @scure API that produces it, so a future author cannot
 * silently double-reverse.
 *
 * Raw `string` cannot be assigned to a `Txid` — consumers must pick the
 * constructor that matches their input.
 */
export type Txid = string & { readonly __brand: "display-order-txid" };

/**
 * Construct a Txid from 32 bytes already in display order.
 *
 * Use this with:
 *   - PSBT `input.txid` (@scure/btc-signer stores this field in display
 *     order — verified by round-tripping `tx.id` through `hex.encode`).
 *
 * Does NOT reverse. If you reverse before calling this, you'll get the
 * internal-order txid back, which won't match anything else in the module.
 */
export function txidFromDisplayBytes(bytes: Uint8Array): Txid {
    if (bytes.length !== 32) {
        throw new Error(
            `txidFromDisplayBytes: expected 32 bytes, got ${bytes.length}`
        );
    }
    let out = "";
    for (const b of bytes) out += b.toString(16).padStart(2, "0");
    return out as Txid;
}

/**
 * Construct a Txid from 32 bytes in internal (wire-format) order.
 *
 * Use this with:
 *   - Raw tx prev-output references as they appear in serialised
 *     Bitcoin transactions (internal field order).
 *
 * REVERSES the bytes before encoding. Do NOT use with @scure's
 * `input.txid` (which is already display order — use
 * {@link txidFromDisplayBytes} for that).
 */
export function txidFromInternalBytes(bytes: Uint8Array): Txid {
    if (bytes.length !== 32) {
        throw new Error(
            `txidFromInternalBytes: expected 32 bytes, got ${bytes.length}`
        );
    }
    const reversed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) reversed[i] = bytes[31 - i];
    let out = "";
    for (const b of reversed) out += b.toString(16).padStart(2, "0");
    return out as Txid;
}

/**
 * Construct a Txid from a pre-display-order hex string (e.g. an indexer
 * response's `ChainTx.txid`, `Transaction.id`). Validates the shape is
 * 64 lowercase hex characters.
 */
export function txidFromString(hex: string): Txid {
    // Indexer's ChainTx.spends[] may include `txid:vout` outpoint
    // strings on CHECKPOINT entries; strip the `:vout` suffix if present.
    const bare = hex.includes(":") ? hex.split(":")[0] : hex;
    if (!/^[0-9a-f]{64}$/.test(bare)) {
        throw new Error(
            `txidFromString: expected 64 lowercase hex chars, got "${hex}"`
        );
    }
    return bare as Txid;
}

/**
 * Branded absolute Bitcoin block height. B9 invariant: a BlockHeight
 * can ONLY be produced via one of two named constructors:
 *   - {@link parseCLTVFromCommitmentScript}(tapleaf) — for protocols that
 *     encode expiry as an absolute-CLTV tapleaf (BIP 65 `<h> OP_CLTV`).
 *   - {@link blockHeightFromRelativeDelay}(blocks, confirmationHeight) —
 *     for protocols (including arkd) that express expiry as a BIP 68
 *     relative block delay via the `VtxoTreeExpiry` PSBT field;
 *     absolute height = commitment's on-chain confirmation height +
 *     delay.
 *
 * No ISO-timestamp / 600s-heuristic constructor exists — that was v1's
 * B9 bug.
 */
export type BlockHeight = number & { readonly __brand: "block-height" };

/**
 * Construct a BlockHeight from a BIP 68 relative block delay + the
 * commitment's on-chain confirmation height. This is how arkd's
 * `VtxoTreeExpiry` PSBT field maps to an absolute batch-expiry height.
 *
 * @param relativeBlocks Block delta from the VtxoTreeExpiry field.
 * @param commitmentConfirmationHeight The block height at which the
 *   commitment tx itself is confirmed on-chain.
 */
export function blockHeightFromRelativeDelay(
    relativeBlocks: number,
    commitmentConfirmationHeight: number
): BlockHeight {
    if (!Number.isInteger(relativeBlocks) || relativeBlocks < 0) {
        throw new Error(
            `blockHeightFromRelativeDelay: invalid relativeBlocks ${relativeBlocks}`
        );
    }
    if (
        !Number.isInteger(commitmentConfirmationHeight) ||
        commitmentConfirmationHeight < 0
    ) {
        throw new Error(
            `blockHeightFromRelativeDelay: invalid commitmentConfirmationHeight ${commitmentConfirmationHeight}`
        );
    }
    const abs = relativeBlocks + commitmentConfirmationHeight;
    if (abs >= CLTV_HEIGHT_THRESHOLD) {
        throw new Error(
            `blockHeightFromRelativeDelay: absolute height ${abs} >= CLTV_HEIGHT_THRESHOLD ${CLTV_HEIGHT_THRESHOLD}`
        );
    }
    return abs as BlockHeight;
}

/** Per BIP 65, absolute block-height CLTV values must be < 500_000_000. */
export const CLTV_HEIGHT_THRESHOLD = 500_000_000;

/** Opcode for OP_CHECKLOCKTIMEVERIFY. */
const OP_CLTV = 0xb1;

/** Minimum push opcode: anything <= 0x4b is a direct-push length byte. */
const MAX_DIRECT_PUSH = 0x4b;

/**
 * Parse a single CScriptNum (minimal encoding, 0-8 bytes, little-endian
 * with a sign bit in the top bit of the final byte) from `bytes` starting
 * at `offset`. Returns {value, nextOffset}. Used to decode the CLTV push.
 */
function readCScriptNum(
    bytes: Uint8Array,
    offset: number,
    len: number
): number {
    if (len === 0) return 0;
    if (len > 8) throw new Error(`CScriptNum oversized: ${len} bytes`);
    let n = 0n;
    for (let i = 0; i < len; i++) {
        n |= BigInt(bytes[offset + i]) << BigInt(8 * i);
    }
    // Sign bit in MSB of the last byte.
    const signBit = 1n << BigInt(8 * len - 1);
    if (n & signBit) {
        n = -(n & (signBit - 1n));
    }
    if (n > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error(`CScriptNum out of range: ${n}`);
    }
    return Number(n);
}

/**
 * Parses a CLTV (CHECKLOCKTIMEVERIFY) push from a commitment tapleaf
 * script and returns it as a {@link BlockHeight}. The script is expected
 * to contain the canonical `<locktime> OP_CHECKLOCKTIMEVERIFY` pattern;
 * we scan for the first OP_CLTV (0xb1) and read its immediate predecessor
 * push as the locktime.
 *
 * This is the ONLY way to construct a BlockHeight in the verification
 * module. The B9 invariant holds — no ISO timestamp + 600s/block
 * heuristic path exists.
 *
 * @throws {Error} if no CLTV push is found, the push is malformed, or
 *   the value is not a block-height (values >= 500_000_000 are
 *   timestamps per BIP 65 and are rejected here).
 */
export function parseCLTVFromCommitmentScript(script: Uint8Array): BlockHeight {
    // Walk the script, tracking the most recent push's value + length.
    // When we hit OP_CLTV, the preceding push is the locktime.
    let i = 0;
    let lastPushValue: number | null = null;
    while (i < script.length) {
        const op = script[i];
        if (op === OP_CLTV) {
            if (lastPushValue === null) {
                throw new Error(
                    "parseCLTVFromCommitmentScript: OP_CLTV with no preceding push"
                );
            }
            if (lastPushValue < 0) {
                throw new Error(
                    `parseCLTVFromCommitmentScript: negative value ${lastPushValue} is not a valid block height (BIP 65 rejects negatives)`
                );
            }
            if (lastPushValue >= CLTV_HEIGHT_THRESHOLD) {
                throw new Error(
                    `parseCLTVFromCommitmentScript: value ${lastPushValue} is a timestamp, not a block height`
                );
            }
            return lastPushValue as BlockHeight;
        }
        // OP_0 pushes a 0 value.
        if (op === 0x00) {
            lastPushValue = 0;
            i += 1;
            continue;
        }
        // OP_1..OP_16 push their numeric value (0x51..0x60).
        if (op >= 0x51 && op <= 0x60) {
            lastPushValue = op - 0x50;
            i += 1;
            continue;
        }
        // OP_1NEGATE = 0x4f.
        if (op === 0x4f) {
            lastPushValue = -1;
            i += 1;
            continue;
        }
        // Direct push: 0x01..0x4b push N bytes.
        if (op >= 0x01 && op <= MAX_DIRECT_PUSH) {
            const len = op;
            const v = readCScriptNum(script, i + 1, len);
            lastPushValue = v;
            i += 1 + len;
            continue;
        }
        // OP_PUSHDATA1 (0x4c), PUSHDATA2 (0x4d), PUSHDATA4 (0x4e).
        if (op === 0x4c) {
            const len = script[i + 1];
            const v = readCScriptNum(script, i + 2, len);
            lastPushValue = v;
            i += 2 + len;
            continue;
        }
        if (op === 0x4d) {
            const len = script[i + 1] | (script[i + 2] << 8);
            const v = readCScriptNum(script, i + 3, len);
            lastPushValue = v;
            i += 3 + len;
            continue;
        }
        if (op === 0x4e) {
            const len =
                (script[i + 1] |
                    (script[i + 2] << 8) |
                    (script[i + 3] << 16) |
                    (script[i + 4] << 24)) >>>
                0; // unsigned to prevent sign-bit overflow
            const v = readCScriptNum(script, i + 5, len);
            lastPushValue = v;
            i += 5 + len;
            continue;
        }
        // Non-push opcode; clear lastPushValue (the locktime push must be
        // the IMMEDIATE predecessor of OP_CLTV).
        lastPushValue = null;
        i += 1;
    }
    throw new Error(
        "parseCLTVFromCommitmentScript: no OP_CHECKLOCKTIMEVERIFY found"
    );
}

/**
 * Decode a BIP 68 nSequence field into the number of blocks it encodes,
 * or `null` if the relative-lock bit is disabled (0x80000000 set) or the
 * type bit (0x400000) signals a time-based lock (we only surface
 * block-count locks — Ark checkpoints use blocks).
 */
export function decodeBip68SequenceBlocks(nSequence: number): number | null {
    if ((nSequence & 0x80000000) !== 0) return null; // disable bit set
    if ((nSequence & 0x00400000) !== 0) return null; // type bit = time
    return nSequence & 0x0000ffff;
}

/**
 * Sighash-type wrapper (B5 invariant). The ONLY constructor is
 * {@link parseSighashFromSchnorrSig} — `SighashType` cannot be built
 * from a bare number. This forces signature-verifier call sites to
 * thread the sighash byte parsed out of the 65-byte Schnorr signature;
 * hardcoded `SigHash.DEFAULT` cannot silently creep into
 * `preimageWitnessV1` invocations (bug B5 from v1 self-review).
 *
 * For signatures where no sighash byte is appended (the 64-byte form
 * per BIP 341 §Default), use {@link sighashTypeDefault} — a labelled
 * constant whose callers visibly opt in.
 */
export type SighashType = number & { readonly __brand: "sighash-type" };

/**
 * Parse the sighash-type byte from a BIP 340 Schnorr signature.
 *
 * BIP 341 §Default: a 64-byte sig means SIGHASH_DEFAULT (0x00). A 65-byte
 * sig carries the sighash byte at `sig[64]`; 0x00 is forbidden (must use
 * the 64-byte form), and common valid values are 0x01 (ALL), 0x02 (NONE),
 * 0x03 (SINGLE), plus the ACP-OR'd variants 0x81/0x82/0x83.
 *
 * This is the sole real-data constructor for {@link SighashType}. The
 * only other entry point is {@link sighashTypeDefault}, which requires
 * the caller to name the default explicitly.
 */
export function parseSighashFromSchnorrSig(sig: Uint8Array): SighashType {
    if (sig.length === 64) {
        return 0x00 as SighashType;
    }
    if (sig.length === 65) {
        const b = sig[64];
        if (b === 0x00) {
            throw new Error(
                "parseSighashFromSchnorrSig: 65-byte sig with sighash=0x00 is invalid (BIP 341: use the 64-byte form)"
            );
        }
        return b as SighashType;
    }
    throw new Error(
        `parseSighashFromSchnorrSig: expected 64- or 65-byte sig, got ${sig.length} bytes`
    );
}

/**
 * The SIGHASH_DEFAULT sentinel (0x00). Exists only so opt-in callers
 * that genuinely need the default (e.g. testing a key-path spend that
 * uses 64-byte sigs) can name it — a bare `0` will not type-check as
 * {@link SighashType}.
 */
export const sighashTypeDefault: SighashType = 0 as SighashType;

/**
 * A prevout (scriptPubKey + value) that a particular input is spending.
 * The sighash computation consumes an array of these, one per input of the
 * spending tx.
 */
export interface Prevout {
    readonly script: Uint8Array;
    readonly amount: bigint;
}

/**
 * Non-empty tuple of prevouts. Every signature path entry MUST carry one
 * prevout per input — bug B1 from v1 self-review where the pipeline only
 * supplied a singular parentOutputScript/parentOutputAmount, crashing on
 * 2-input Arkoor txs with `sig.prevout-count-mismatch`.
 *
 * The non-empty tuple type makes `SignaturePathEntry` un-constructable
 * without supplying at least one prevout; the runtime assertion in
 * {@link makeSignaturePathEntry} enforces `prevouts.length === inputsLength`.
 */
export type PerInputPrevouts = readonly [Prevout, ...Prevout[]];

export interface SignaturePathEntry {
    readonly tx: Transaction;
    readonly perInputPrevouts: PerInputPrevouts;
}

/**
 * Constructs a SignaturePathEntry. Asserts prevouts.length === tx.inputsLength
 * at construction time so a mismatch fails before verification runs.
 */
export function makeSignaturePathEntry(
    tx: Transaction,
    prevouts: readonly Prevout[]
): SignaturePathEntry {
    if (prevouts.length === 0) {
        throw new Error("makeSignaturePathEntry: prevouts must not be empty");
    }
    if (prevouts.length !== tx.inputsLength) {
        throw new Error(
            `makeSignaturePathEntry: prevouts.length (${prevouts.length}) !== tx.inputsLength (${tx.inputsLength})`
        );
    }
    return {
        tx,
        perInputPrevouts: prevouts as unknown as PerInputPrevouts,
    };
}

/**
 * Simple Result<Ok, Err> tagged union. Used where a function would
 * otherwise silently return a sentinel (e.g. vout=0 on resolution
 * failure — bug B7 from v1 self-review).
 */
export type Result<T, E> =
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: E };

export function ok<T>(value: T): Result<T, never> {
    return { ok: true, value };
}

export function err<E>(error: E): Result<never, E> {
    return { ok: false, error };
}

/**
 * Walker-stage commitment metadata. At DAG-construction time the walker
 * knows the txid and can observe the vout each child claims; the
 * {@link batchScript}, {@link batchAmount}, and {@link batchExpiryHeight}
 * are only available after P5 (on-chain resolution + CLTV parse).
 *
 * A walker {@link UnresolvedCommitmentInfo} cannot be passed to a P5
 * anchor-verifier slot expecting {@link ResolvedCommitmentInfo} —
 * TypeScript rejects the assignment. This is how the B9 invariant is
 * preserved across stages: the "placeholder BlockHeight" cast that v1
 * needed has no home in v2's types.
 */
export interface UnresolvedCommitmentInfo {
    readonly txid: Txid;
    /**
     * The vouts each child claims to spend from this commitment. Array
     * form (not a single number) so multi-input Arkoor DAGs, where two
     * children spend different vouts of the same commitment, don't lose
     * one of the edges — bug #8 from the P0-P2 review.
     */
    readonly claimedVouts: readonly number[];
}

/**
 * Resolved commitment metadata. `batchScript`, `batchAmount`, `vout`
 * are required (B4 / B7 invariants — no silent defaults). The
 * `batchExpiryHeight` is **optional** because §3.1.3's core checks
 * (confirmed / output-matches / unspent) do not depend on it, and
 * different protocols encode expiry differently (block-based CLTV
 * tapleaf vs seconds-based relative `VtxoTreeExpiry` PSBT field). When
 * present it must come from one of the two B9-approved constructors:
 * {@link parseCLTVFromCommitmentScript} or
 * {@link blockHeightFromRelativeDelay}. When absent, the anchor
 * verifier's `anchor.expiry-not-passed` row emits UNSUPPORTED; the
 * other three anchor rows still run.
 */
export interface ResolvedCommitmentInfo {
    readonly txid: Txid;
    readonly vout: number;
    readonly batchScript: Uint8Array;
    readonly batchAmount: bigint;
    readonly batchExpiryHeight?: BlockHeight;
}

/**
 * @deprecated Legacy alias while the module transitions from the
 * walker's unresolved shape to the post-P5 resolved shape. New code
 * should reference {@link ResolvedCommitmentInfo} or
 * {@link UnresolvedCommitmentInfo} directly.
 */
export type CommitmentInfo = ResolvedCommitmentInfo;

export type CommitmentResolveError =
    | "commitment-vout-unresolved"
    | "commitment-script-missing"
    | "commitment-amount-missing"
    | "commitment-expiry-unparseable";

/**
 * Per-path broadcast schedule for the unilateral-exit executor. The
 * verification module exposes only the per-path shape; no global-offset
 * constructor exists — bug B10 from v1 self-review where
 * `broadcastSchedule` used `max(confirmationHeight) + i` ignoring
 * per-path CSV accumulation in multi-root bundles.
 */
export interface PerPathSchedule {
    readonly pathIndex: number;
    readonly entries: ReadonlyArray<{
        readonly txid: Txid;
        readonly earliestBlock: BlockHeight;
        readonly broadcastOrder: number;
    }>;
}

/**
 * Error taxonomy — 4 stable kinds for consumer tools (tamper demo,
 * browser demo) to dispatch on. Codes are kebab-case strings per
 * convention; INVARIANT codes are stable across releases so the tamper
 * demo can assert on them.
 */
export type VerificationErrorKind =
    | "DATA"
    | "NETWORK"
    | "INVARIANT"
    | "UNSUPPORTED";

export interface VerificationError {
    readonly kind: VerificationErrorKind;
    readonly code: string;
    readonly message: string;
    readonly source?: string;
    readonly context?: Readonly<Record<string, unknown>>;
}

/**
 * A single check row in the verification trace. Consumed by tamper demo
 * (D1), verbose tracing (D2), and browser demo (D3).
 */
export interface CheckResult {
    readonly name: string;
    readonly passed: boolean;
    readonly details?: string;
    readonly durationMs: number;
    readonly evidence?: Readonly<Record<string, unknown>>;
}

/**
 * Aggregate verification result. `valid` is true iff every check passed
 * and no thrown errors were recorded. Partial-failure semantics: the
 * pipeline never throws for attack-catching reasons — failures land as
 * CheckResult(passed:false) or VerificationError entries in `errors[]`.
 */
export interface VerificationResult {
    readonly valid: boolean;
    readonly checks: readonly CheckResult[];
    readonly errors: readonly VerificationError[];
    readonly totalDurationMs: number;
    readonly tier: VerificationTier;
}

export type VerificationTier = "chain" | "script" | "full";

export interface VerificationOptions {
    readonly tier?: VerificationTier;
    readonly verbose?: boolean;
    readonly signal?: AbortSignal;
    readonly minConfirmations?: number;
}
