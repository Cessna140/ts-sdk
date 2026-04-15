import type { CheckResult } from "./types";

export interface TimelockVerifierInput {
    readonly path: readonly unknown[];
    readonly signal?: AbortSignal;
}

export async function verifyTimelocks(
    _input: TimelockVerifierInput
): Promise<readonly CheckResult[]> {
    throw new Error("verifyTimelocks: not implemented until P4");
}
