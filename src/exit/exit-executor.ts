import type { ExitDataRepository } from "./exit-data-store";

export interface ExitExecutionStep {
    readonly name: string;
    readonly succeeded: boolean;
    readonly details?: string;
    readonly durationMs: number;
}

export interface ExitExecutionResult {
    readonly broadcasted: readonly string[]; // txids in broadcast order
    readonly steps: readonly ExitExecutionStep[];
    readonly errors: readonly { code: string; message: string }[];
}

export interface ExecuteUnilateralExitInput {
    readonly vtxoId: string;
    readonly repository: ExitDataRepository;
    readonly onchainProvider: unknown;
    readonly signal?: AbortSignal;
}

/**
 * Executes a unilateral exit using only locally-stored bundle data + an
 * on-chain provider. Never contacts the ASP's IndexerService. Never
 * throws — returns a typed {@link ExitExecutionResult} with per-step
 * trace + structured errors (mirrors verifier partial-failure discipline).
 *
 * Stub — implementation lands in P6.
 */
export async function executeUnilateralExit(
    _input: ExecuteUnilateralExitInput
): Promise<ExitExecutionResult> {
    return {
        broadcasted: [],
        steps: [],
        errors: [
            {
                code: "executor.not-implemented",
                message: "executeUnilateralExit is a P0 scaffold",
            },
        ],
    };
}
