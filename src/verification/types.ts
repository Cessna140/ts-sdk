import type { Transaction } from "@scure/btc-signer";

/**
 * Branded display-order txid string. Sole constructor is {@link toDisplayTxid}.
 * Prevents accidental comparison between internal (little-endian) and display
 * (reversed) byte-orders — bug B2 from v1 self-review.
 */
export type Txid = string & { readonly __brand: "display-order-txid" };

/**
 * Converts a 32-byte txid (in @scure/btc-signer internal little-endian order)
 * to a display-order hex string. All Txid values flowing through the
 * verification module must be constructed via this function — raw hex strings
 * or byte arrays cannot be compared as Txid values without this conversion.
 */
export function toDisplayTxid(bytes: Uint8Array): Txid {
    if (bytes.length !== 32) {
        throw new Error(
            `toDisplayTxid: expected 32 bytes, got ${bytes.length}`
        );
    }
    const reversed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) reversed[i] = bytes[31 - i];
    let out = "";
    for (const b of reversed) out += b.toString(16).padStart(2, "0");
    return out as Txid;
}

/**
 * Branded absolute Bitcoin block height. Sole constructor is
 * {@link parseCLTVFromCommitmentScript} — a BlockHeight cannot be produced
 * from an ISO timestamp + 600s/block heuristic (bug B9 from v1 self-review).
 */
export type BlockHeight = number & { readonly __brand: "block-height" };

/**
 * Parses a CLTV (CHECKLOCKTIMEVERIFY) push value from a commitment tapleaf
 * script and returns it as a BlockHeight. This is the ONLY way to construct
 * a BlockHeight in the verification module. See also {@link chain-walker}
 * where it is used to populate {@link CommitmentInfo.batchExpiryHeight}.
 *
 * @throws {Error} if no CLTV push is found or the pushed value is not a
 *   block-height-shaped CScriptNum.
 */
export function parseCLTVFromCommitmentScript(
    _script: Uint8Array
): BlockHeight {
    // Implementation lands in Phase 2 (commit: "checkpoint CSV coherence +
    // CLTV-direct expiry parsing"). The exported signature is the invariant.
    throw new Error("parseCLTVFromCommitmentScript: not implemented until P2");
}

/**
 * Sighash-type wrapper. A non-default constructor is required so that
 * {@link preimageWitnessV1Typed} callers must thread the parsed sighash byte
 * from the 65-byte Schnorr signature — hardcoded SigHash.DEFAULT cannot
 * silently creep in (bug B5 from v1 self-review).
 */
export type SighashType = number & { readonly __brand: "sighash-type" };

export function toSighashType(byte: number): SighashType {
    if (!Number.isInteger(byte) || byte < 0 || byte > 0xff) {
        throw new Error(`toSighashType: invalid byte ${byte}`);
    }
    return byte as SighashType;
}

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
 * Commitment-transaction metadata resolved by the DAG walker for each
 * commitment root. Every field is required — no optional batchAmount,
 * no default vout — which kills bug B4 (value-conservation silently
 * skipped at commitment boundary) and bug B7 (vout silently defaulting
 * to 0) from v1 self-review.
 */
export interface CommitmentInfo {
    readonly txid: Txid;
    readonly vout: number;
    readonly batchScript: Uint8Array;
    readonly batchAmount: bigint;
    readonly batchExpiryHeight: BlockHeight;
}

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
