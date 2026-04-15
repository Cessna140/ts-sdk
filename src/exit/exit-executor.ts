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
 * throws in production — returns a typed {@link ExitExecutionResult}
 * with per-step trace + structured errors (mirrors verifier
 * partial-failure discipline).
 *
 * The P0 scaffold throws — consistent with every other stub in the
 * verification + exit modules — so the "not yet implemented" state is
 * unmistakable. Once P6 lands the real executor, the function returns
 * the typed result without throwing.
 */
export async function executeUnilateralExit(
    _input: ExecuteUnilateralExitInput
): Promise<ExitExecutionResult> {
    throw new Error("executeUnilateralExit: not implemented until P6");
}
