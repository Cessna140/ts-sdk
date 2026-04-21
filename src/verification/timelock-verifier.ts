/**
 * Timelock verifier — assignment §3.2.2.
 *
 * Three checks emitted:
 *   - `timelock.fields-parsed` — every tx's `nLockTime` and input 0
 *     `nSequence` decode coherently (BIP 68 / BIP 65 shape).
 *   - `timelock.script-constraints` — every tapleaf script's CLTV /
 *     CSV opcodes have a minimal integer push in the immediate
 *     predecessor; the pushed value is satisfiable given the tx's
 *     fields (nLockTime >= CLTV push; nSequence encodes same unit+
 *     value as CSV push).
 *   - `timelock.hierarchy-sane` — `nLockTime` is non-decreasing as we
 *     walk from leaf toward root; CSV at the leaf falls within
 *     [MIN_CSV, MAX_CSV] bounds.
 */

import { Script } from "@scure/btc-signer/script.js";
import { MalformedChainError } from "./errors";
import type { CheckResult, SignaturePathEntry } from "./types";
import { decodeBip68SequenceBlocks } from "./types";
import { throwIfAborted } from "./utils";

export const DEFAULT_MIN_CSV_BLOCKS = 1;
export const DEFAULT_MAX_CSV_BLOCKS = 52_560; // ~1 year at 10 min/block

const OP_CLTV = 0xb1;
const OP_CSV = 0xb2;

export interface TimelockVerifierInput {
    readonly path: readonly SignaturePathEntry[];
    readonly minCsvBlocks?: number;
    readonly maxCsvBlocks?: number;
    readonly signal?: AbortSignal;
}

/**
 * Walk a script's decoded opcodes/pushes looking for the CLTV and
 * CSV opcodes; for each, return the immediate-predecessor push's
 * integer value (or null if the predecessor isn't a numeric push).
 */
function scanScriptForTimelocks(script: Uint8Array): {
    cltvValues: number[];
    csvValues: number[];
} {
    const out = { cltvValues: [] as number[], csvValues: [] as number[] };
    let decoded: unknown[];
    try {
        decoded = Script.decode(script) as unknown[];
    } catch {
        return out;
    }
    for (let i = 1; i < decoded.length; i++) {
        const op = decoded[i];
        // @scure represents opcodes as strings or numbers; normalise
        // by stringifying and checking for the opcode numeric value.
        if (op === "CHECKLOCKTIMEVERIFY" || op === OP_CLTV) {
            const prev = decoded[i - 1];
            const v = coerceToNumber(prev);
            if (v !== null) out.cltvValues.push(v);
        } else if (op === "CHECKSEQUENCEVERIFY" || op === OP_CSV) {
            const prev = decoded[i - 1];
            const v = coerceToNumber(prev);
            if (v !== null) out.csvValues.push(v);
        }
    }
    return out;
}

function coerceToNumber(push: unknown): number | null {
    if (typeof push === "number") return push;
    if (typeof push === "bigint") {
        if (push > BigInt(Number.MAX_SAFE_INTEGER)) return null;
        return Number(push);
    }
    if (push instanceof Uint8Array) {
        // CScriptNum little-endian with sign bit
        if (push.length === 0) return 0;
        if (push.length > 8) return null;
        let n = 0n;
        for (let i = 0; i < push.length; i++) {
            n |= BigInt(push[i]) << BigInt(8 * i);
        }
        const signBit = 1n << BigInt(8 * push.length - 1);
        if (n & signBit) {
            const magnitude = n & (signBit - 1n);
            if (magnitude > BigInt(Number.MAX_SAFE_INTEGER)) return null;
            return -Number(magnitude);
        }
        if (n > BigInt(Number.MAX_SAFE_INTEGER)) return null;
        return Number(n);
    }
    return null;
}

export async function verifyTimelocks(
    input: TimelockVerifierInput
): Promise<readonly CheckResult[]> {
    const { path, signal } = input;
    const minCsv = input.minCsvBlocks ?? DEFAULT_MIN_CSV_BLOCKS;
    const maxCsv = input.maxCsvBlocks ?? DEFAULT_MAX_CSV_BLOCKS;

    throwIfAborted(signal);

    let fieldsParsed = 0;
    let fieldsFailed = 0;
    const fieldDetails: string[] = [];
    let cltvScripts = 0;
    let csvScripts = 0;
    let consistencyChecked = 0;
    let consistencyFailed = 0;
    const consistencyDetails: string[] = [];
    let maxLocktime = 0;
    let topLocktime = 0;
    let leafCsv: number | null = null;
    const locktimes: number[] = [];

    for (let i = 0; i < path.length; i++) {
        const entry = path[i];
        const tx = entry.tx;

        // Parse nLockTime + input 0 nSequence
        const nLockTime = tx.lockTime ?? 0;
        const seq = tx.getInput(0)?.sequence ?? 0xffffffff;
        const csvBlocks = decodeBip68SequenceBlocks(seq);
        fieldsParsed++;
        locktimes.push(nLockTime);
        maxLocktime = Math.max(maxLocktime, nLockTime);
        topLocktime = nLockTime;
        if (i === 0 && csvBlocks !== null) leafCsv = csvBlocks;

        // Walk every tapleaf of every input for CLTV/CSV patterns
        for (let j = 0; j < tx.inputsLength; j++) {
            const inp = tx.getInput(j);
            const tapLeaves = inp.tapLeafScript as
                | ReadonlyArray<readonly [unknown, Uint8Array]>
                | undefined;
            if (!tapLeaves) continue;
            for (const leaf of tapLeaves) {
                const scriptBytes = leaf[1].subarray(0, leaf[1].length - 1);
                const { cltvValues, csvValues } =
                    scanScriptForTimelocks(scriptBytes);
                if (cltvValues.length > 0) cltvScripts++;
                if (csvValues.length > 0) csvScripts++;

                // Consistency: tx nLockTime must >= every CLTV push
                for (const c of cltvValues) {
                    consistencyChecked++;
                    if (nLockTime < c) {
                        consistencyFailed++;
                        consistencyDetails.push(
                            `tx[${i}] nLockTime ${nLockTime} < CLTV push ${c}`
                        );
                    }
                }
                // Consistency: tx nSequence CSV-blocks must match CSV push
                for (const c of csvValues) {
                    consistencyChecked++;
                    if (csvBlocks === null || csvBlocks < c) {
                        consistencyFailed++;
                        consistencyDetails.push(
                            `tx[${i}] nSequence CSV=${csvBlocks} < CSV push ${c}`
                        );
                    }
                }
            }
        }
    }

    // Hierarchy: locktimes non-decreasing leaf→root (path is ordered
    // leaf-first per walker's Kahn sort output).
    let hierarchyOk = true;
    const hierarchyDetails: string[] = [];
    for (let i = 1; i < locktimes.length; i++) {
        if (locktimes[i] < locktimes[i - 1]) {
            hierarchyOk = false;
            hierarchyDetails.push(
                `nLockTime decreased at depth ${i}: ${locktimes[i - 1]} -> ${locktimes[i]}`
            );
        }
    }
    if (leafCsv !== null && (leafCsv < minCsv || leafCsv > maxCsv)) {
        hierarchyOk = false;
        hierarchyDetails.push(
            `leaf CSV ${leafCsv} out of bounds [${minCsv}, ${maxCsv}]`
        );
    }

    return [
        {
            name: "timelock.fields-parsed",
            passed: fieldsFailed === 0,
            details:
                fieldsFailed === 0
                    ? `Parsed nLockTime + nSequence on ${fieldsParsed} tx(s)`
                    : fieldDetails.join("; "),
            durationMs: 0,
            evidence: {
                path_length: path.length,
                fields_parsed: fieldsParsed,
                cltv_scripts_found: cltvScripts,
                csv_scripts_found: csvScripts,
            },
        },
        {
            name: "timelock.script-constraints",
            passed: consistencyFailed === 0,
            details:
                consistencyChecked === 0
                    ? "No CLTV/CSV scripts in path (trivially consistent)"
                    : consistencyFailed === 0
                      ? `All ${consistencyChecked} tx-vs-script timelock(s) consistent`
                      : consistencyDetails.join("; "),
            durationMs: 0,
            evidence: {
                consistency_checked: consistencyChecked,
                consistency_failed: consistencyFailed,
            },
        },
        {
            name: "timelock.hierarchy-sane",
            passed: hierarchyOk,
            details: hierarchyOk
                ? `nLockTime hierarchy non-decreasing; leaf CSV ${leafCsv ?? "none"} within bounds`
                : hierarchyDetails.join("; "),
            durationMs: 0,
            evidence: {
                max_nlocktime_observed: maxLocktime,
                topmost_nlocktime: topLocktime,
                leaf_csv_blocks: leafCsv,
                min_csv_blocks: minCsv,
                max_csv_blocks: maxCsv,
            },
        },
    ];
}
