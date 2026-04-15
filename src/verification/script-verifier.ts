import type { CheckResult } from "./types";

/**
 * Script-tree verifier (assignment §3.2.1 + v2 addition
 * `script.vtxotaprootree-valid`).
 *
 * Stub — implementation lands in P4.
 */
export interface ScriptVerifierInput {
    readonly path: readonly unknown[];
    readonly signal?: AbortSignal;
}

export async function verifyScripts(
    _input: ScriptVerifierInput
): Promise<readonly CheckResult[]> {
    throw new Error("verifyScripts: not implemented until P4");
}
