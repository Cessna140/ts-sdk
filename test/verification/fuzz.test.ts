/**
 * Adversarial fuzz suite — random-byte PSBT mutation × N per verifier.
 *
 * Goal: prove the verifier never hangs, never throws an uncaught
 * exception, and always terminates ≤5s on a single VTXO chain. Tamper
 * detection isn't the point here (tamper-demo handles that); this
 * suite is a robustness smoke test against malformed/random input.
 *
 * Failure surface:
 *  - hang (≥ MAX_RUN_MS) → vitest test-timeout fails the run
 *  - thrown exception bubbling out of verifyVtxo → caught here as a
 *    test failure with the seed printed for repro
 *  - invalid VerificationResult shape → assertion failure
 *
 * Reproduction: any failure logs the seed; rerun with that seed to
 * reproduce the exact mutation sequence.
 */

import { describe, expect, it } from "vitest";
import { base64 } from "@scure/base";

import { verifyVtxo } from "../../src/verification/index";
import {
    buildMockChain,
    makeMockIndexerProvider,
    makeMockOnchainProvider,
} from "./helpers";

const FUZZ_RUNS = 100;
const MAX_RUN_MS = 5_000;

/** Deterministic PRNG (xorshift32) so seeds reproduce exactly. */
function rng(seed: number): () => number {
    let s = seed >>> 0;
    if (s === 0) s = 0x12345678;
    return () => {
        s ^= s << 13;
        s ^= s >>> 17;
        s ^= s << 5;
        s >>>= 0;
        return s / 0x100000000;
    };
}

/**
 * Mutate `count` random bytes in the PSBT base64 (xor each with a
 * random non-zero byte). Returns the mutated base64 string.
 */
function fuzzPsbt(psbt: string, rand: () => number, count: number): string {
    const bytes = base64.decode(psbt);
    for (let i = 0; i < count; i++) {
        const idx = Math.floor(rand() * bytes.length);
        const xor = 1 + Math.floor(rand() * 255);
        bytes[idx] ^= xor;
    }
    return base64.encode(bytes);
}

describe("fuzz: verifier never hangs or throws on random PSBT mutations", () => {
    it(
        `100 random mutations × Tier 1: every run terminates ≤5s with a structured result`,
        { timeout: 120_000 },
        async () => {
            const baseFx = buildMockChain({ depth: 2 });
            // One mock-onchain shared across runs (no network calls).
            const onchain = makeMockOnchainProvider({
                txOutputsByTxid: {
                    [baseFx.commitmentTxid]: [
                        {
                            script: new Uint8Array(34).fill(0x51),
                            amount: 100_000n,
                        },
                    ],
                },
            });

            for (let run = 0; run < FUZZ_RUNS; run++) {
                const seed = (Date.now() ^ (run * 0x9e3779b1)) >>> 0;
                const rand = rng(seed);
                // Mutate 1-8 bytes (vary intensity across runs).
                const mutationCount = 1 + Math.floor(rand() * 8);
                const fuzzed = baseFx.virtualTxs.map((psbt) =>
                    fuzzPsbt(psbt, rand, mutationCount)
                );
                const indexer = makeMockIndexerProvider({
                    vtxoChain: baseFx.vtxoChain,
                    virtualTxs: fuzzed,
                });
                const start = Date.now();
                let result;
                try {
                    result = await verifyVtxo({
                        vtxoId: baseFx.leaf,
                        indexerProvider: indexer,
                        onchainProvider: onchain,
                    });
                } catch (e) {
                    // eslint-disable-next-line no-console
                    console.error(
                        `Fuzz seed ${seed} (run ${run}, mutations ${mutationCount}) — uncaught throw:`,
                        e instanceof Error ? e.message : String(e)
                    );
                    throw new Error(
                        `verifyVtxo threw uncaught at seed ${seed}: ${e instanceof Error ? e.message : String(e)}`
                    );
                }
                const elapsed = Date.now() - start;
                if (elapsed > MAX_RUN_MS) {
                    throw new Error(
                        `Fuzz seed ${seed} took ${elapsed}ms (>${MAX_RUN_MS}ms bound)`
                    );
                }
                // Result shape sanity — verifier must always return a
                // structured VerificationResult, never a partial / null.
                expect(typeof result.valid).toBe("boolean");
                expect(Array.isArray(result.checks)).toBe(true);
                expect(Array.isArray(result.errors)).toBe(true);
                expect(typeof result.totalDurationMs).toBe("number");
            }
        }
    );

    it(
        "indexer-response mutations: chain field corrupted; verifier returns errors[] entry rather than throwing",
        { timeout: 60_000 },
        async () => {
            const baseFx = buildMockChain({ depth: 2 });
            const onchain = makeMockOnchainProvider({});
            // Drop the chain entirely — empty chain response.
            const indexer = makeMockIndexerProvider({
                vtxoChain: { chain: [] },
                virtualTxs: [],
            });
            const result = await verifyVtxo({
                vtxoId: baseFx.leaf,
                indexerProvider: indexer,
                onchainProvider: onchain,
            }).catch((e) => {
                // The empty-chain case throws MalformedChainError; the
                // pipeline catches it via recordThrown. If a throw
                // escapes here, that's a regression.
                throw new Error(
                    `verifyVtxo threw on empty chain instead of returning errors[]: ${e instanceof Error ? e.message : String(e)}`
                );
            });
            expect(result.errors.length).toBeGreaterThan(0);
            expect(result.valid).toBe(false);
        }
    );
});
