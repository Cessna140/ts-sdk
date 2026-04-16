#!/usr/bin/env tsx
/**
 * M3 — Tamper demo CLI.
 *
 * Creates a real VTXO on nigiri regtest, then runs `verifyVtxo` under
 * 4 attack scenarios that each flip a documented check row (or surface
 * a specific errors[] entry) without throwing. Material reviewer-facing
 * evidence that the verifier catches real tamper on real arkd data.
 *
 * Usage: `pnpm tamper-demo` (requires `nigiri start --ark`).
 *        `pnpm tamper-demo --verbose` to print the full trace.
 */

import { base64 } from "@scure/base";
import { Transaction } from "@scure/btc-signer/transaction.js";
import { execSync } from "child_process";
// Node 22 lacks a global EventSource; the SDK's settle() path uses
// Server-Sent Events. Polyfill before any SDK module loads.
import { EventSource } from "eventsource";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).EventSource = EventSource;

import {
    EsploraProvider,
    RestIndexerProvider,
    SingleKey,
    Wallet,
    InMemoryWalletRepository,
    InMemoryContractRepository,
    type Outpoint,
} from "../src/index";
import { verifyVtxo } from "../src/verification";
import type { VerificationResult } from "../src/verification/types";
import type { VtxoChain, ChainTx } from "../src/providers/indexer";

const ARK_URL = "http://localhost:7070";
const ESPLORA_URL = "http://localhost:3000";
const ARKD_EXEC = "docker exec -t ark";

const VERBOSE = process.argv.includes("--verbose");

function log(msg: string): void {
    console.log(msg);
}

function header(title: string): void {
    console.log(`\n\x1b[1;36m== ${title} ==\x1b[0m`);
}

function sh(cmd: string): string {
    return execSync(cmd, { encoding: "utf8" }).trim();
}

function mineBlock(): void {
    const addr = sh(
        `docker exec bitcoin bitcoin-cli -regtest -rpcuser=admin1 -rpcpassword=123 getnewaddress "" bech32m`
    );
    sh(
        `docker exec bitcoin bitcoin-cli -regtest -rpcuser=admin1 -rpcpassword=123 generatetoaddress 1 ${addr}`
    );
}

async function waitForTx(txid: string): Promise<void> {
    const deadline = Date.now() + 20_000;
    while (Date.now() < deadline) {
        try {
            const r = await fetch(`${ESPLORA_URL}/tx/${txid}`);
            if (r.ok) return;
        } catch {
            // noop
        }
        await new Promise((r) => setTimeout(r, 500));
    }
    throw new Error(`Timeout waiting for ${txid}`);
}

async function waitForConfirmed(txid: string): Promise<void> {
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
        try {
            const r = await fetch(`${ESPLORA_URL}/tx/${txid}/status`);
            if (r.ok) {
                const s = await r.json();
                if (s.confirmed) return;
            }
        } catch {
            // noop
        }
        await new Promise((r) => setTimeout(r, 500));
    }
    throw new Error(`Timeout waiting for confirmation of ${txid}`);
}

async function createLiveVtxo(): Promise<Outpoint> {
    header("Setup: creating a live VTXO on nigiri");
    // Redeem a faucet note to seed spendable balance for the ark CLI.
    try {
        sh(
            `${ARKD_EXEC} ark init --password secret --server-url localhost:7070 --explorer http://chopsticks:3000`
        );
    } catch {
        // already initialized
    }
    const note = sh(`${ARKD_EXEC} arkd note --amount 200000`);
    sh(`${ARKD_EXEC} ark redeem-notes -n ${note} --password secret`);

    const identity = SingleKey.fromRandomBytes();
    const wallet = await Wallet.create({
        identity,
        arkServerUrl: ARK_URL,
        onchainProvider: new EsploraProvider(ESPLORA_URL, {
            forcePolling: true,
            pollingInterval: 2000,
        }),
        storage: {
            walletRepository: new InMemoryWalletRepository(),
            contractRepository: new InMemoryContractRepository(),
        },
        settlementConfig: false,
    });

    const address = await wallet.getAddress();
    if (!address) throw new Error("No offchain address");
    sh(`${ARKD_EXEC} ark send --to ${address} --amount 1000 --password secret`);
    await new Promise((r) => setTimeout(r, 1_500));
    const vtxos = await wallet.getVtxos();
    if (vtxos.length === 0) throw new Error("No VTXOs received");
    const inputs = vtxos;
    await wallet.settle({
        inputs,
        outputs: [
            {
                address,
                amount: BigInt(inputs.reduce((s, v) => s + v.value, 0)),
            },
        ],
    });
    const after = await wallet.getVtxos();
    if (after.length === 0) throw new Error("No VTXOs after settle");
    const v = after[0];
    log(`  leaf txid: ${v.txid}:${v.vout}`);
    return { txid: v.txid, vout: v.vout };
}

function renderResult(label: string, result: VerificationResult): void {
    const failedChecks = result.checks.filter((c) => !c.passed);
    const passedCount = result.checks.filter((c) => c.passed).length;
    log(`  valid: ${result.valid}`);
    log(
        `  checks: ${passedCount}/${result.checks.length} passed; ${failedChecks.length} failed`
    );
    log(`  errors[]: ${result.errors.length}`);
    if (failedChecks.length > 0) {
        log(`  ▸ Flipped rows:`);
        for (const c of failedChecks) {
            log(`     ✗ ${c.name}: ${c.details}`);
        }
    }
    if (result.errors.length > 0) {
        log(`  ▸ errors[] entries:`);
        for (const e of result.errors) {
            log(`     ✗ [${e.kind}] ${e.code}: ${e.message}`);
        }
    }
    if (VERBOSE) {
        log(`  ▸ Full trace:`);
        for (const c of result.checks) {
            const mark = c.passed ? "\x1b[32m✓\x1b[0m" : "\x1b[31m✗\x1b[0m";
            log(`     ${mark} ${c.name} (${c.durationMs}ms)`);
        }
    }
}

interface Attack {
    name: string;
    description: string;
    expectedCatch: string; // check row name OR errors[] code
    mutate: (baseIndexer: RestIndexerProvider) => RestIndexerProvider;
}

function wrapIndexer(
    base: RestIndexerProvider,
    overrides: Partial<RestIndexerProvider>
): RestIndexerProvider {
    return new Proxy(base, {
        get(target, p) {
            if (p in overrides) {
                return (overrides as Record<string, unknown>)[p as string];
            }
            const orig = Reflect.get(target, p);
            return typeof orig === "function" ? orig.bind(target) : orig;
        },
    }) as RestIndexerProvider;
}

async function runAttack(
    attack: Attack,
    baseIndexer: RestIndexerProvider,
    onchain: EsploraProvider,
    vtxo: Outpoint
): Promise<{
    caught: boolean;
    catcher: string | null;
    result: VerificationResult;
}> {
    header(`ATTACK: ${attack.name}`);
    log(`  ${attack.description}`);
    log(`  Expected catcher: ${attack.expectedCatch}`);
    const mutated = attack.mutate(baseIndexer);
    const result = await verifyVtxo({
        vtxoId: vtxo,
        indexerProvider: mutated,
        onchainProvider: onchain,
        options: { minConfirmations: 1 },
    });
    renderResult(attack.name, result);
    // Determine which row (if any) caught the attack.
    const failedCheck = result.checks.find(
        (c) => c.name === attack.expectedCatch && !c.passed
    );
    const matchedError = result.errors.find(
        (e) => e.code === attack.expectedCatch
    );
    const caught = !!failedCheck || !!matchedError;
    const catcher = failedCheck?.name ?? matchedError?.code ?? null;
    return { caught, catcher, result };
}

async function main(): Promise<void> {
    console.log("\x1b[1;33m=== Tamper demo (M3) ===\x1b[0m");
    console.log("Requires nigiri running with `nigiri start --ark`.\n");

    const baseIndexer = new RestIndexerProvider(ARK_URL);
    const onchain = new EsploraProvider(ESPLORA_URL);

    const vtxo = await createLiveVtxo();

    const chain = await baseIndexer.getVtxoChain(vtxo);
    const commitment = chain.chain.find(
        (n) => n.type === "INDEXER_CHAINED_TX_TYPE_COMMITMENT"
    );
    if (!commitment) throw new Error("No commitment in chain");
    await waitForTx(commitment.txid);
    mineBlock();
    await waitForConfirmed(commitment.txid);

    // Baseline run (no tamper) to establish expected green trace.
    header("Baseline (no tamper) — expected all rows green");
    const baseline = await verifyVtxo({
        vtxoId: vtxo,
        indexerProvider: baseIndexer,
        onchainProvider: onchain,
        options: { minConfirmations: 1 },
    });
    renderResult("baseline", baseline);

    const attacks: Attack[] = [
        {
            name: "1. Signature byte flip",
            description:
                "Parse the leaf PSBT, flip a byte in input 0's tapKeySig, re-serialize",
            expectedCatch: "sig.schnorr-valid",
            mutate: (base) =>
                wrapIndexer(base, {
                    getVirtualTxs: async (txids: string[]) => {
                        const r = await base.getVirtualTxs(txids);
                        const mutated = r.txs.map((psbt, i) => {
                            if (i !== 0) return psbt;
                            const tx = Transaction.fromPSBT(
                                base64.decode(psbt),
                                { allowUnknown: true }
                            );
                            const inp = tx.getInput(0);
                            if (!inp.tapKeySig) return psbt;
                            const sig = new Uint8Array(inp.tapKeySig);
                            sig[10] ^= 0x80; // flip a sig byte
                            tx.updateInput(0, { tapKeySig: sig });
                            return base64.encode(tx.toPSBT());
                        });
                        return { txs: mutated, page: r.page };
                    },
                } as unknown as Partial<RestIndexerProvider>),
        },
        {
            name: "2. Parent txid swap",
            description:
                "Rewrite the leaf's spends[] to point at a bogus txid — no such tx in chain",
            expectedCatch: "chain.parent-missing",
            mutate: (base) =>
                wrapIndexer(base, {
                    getVtxoChain: (async (outpoint: Outpoint) => {
                        const real = await base.getVtxoChain(outpoint);
                        const tampered: VtxoChain = {
                            ...real,
                            chain: real.chain.map((c: ChainTx, i: number) =>
                                i === 0
                                    ? {
                                          ...c,
                                          spends: ["ff".repeat(32)],
                                      }
                                    : c
                            ),
                        };
                        return tampered;
                    }) as unknown as RestIndexerProvider["getVtxoChain"],
                } as unknown as Partial<RestIndexerProvider>),
        },
        {
            name: "3. Commitment removed from chain",
            description:
                "Drop the COMMITMENT entry from the indexer's chain response — walker can't build DAG",
            expectedCatch: "chain.missing-input",
            mutate: (base) =>
                wrapIndexer(base, {
                    getVtxoChain: (async (outpoint: Outpoint) => {
                        const real = await base.getVtxoChain(outpoint);
                        return {
                            ...real,
                            chain: real.chain
                                .filter(
                                    (c: ChainTx) =>
                                        c.type !==
                                        "INDEXER_CHAINED_TX_TYPE_COMMITMENT"
                                )
                                // Make the remaining top tx a leaf
                                // pointing at nothing.
                                .map((c: ChainTx) =>
                                    c.spends.some((s) => s === commitment.txid)
                                        ? { ...c, spends: [] }
                                        : c
                                ),
                        } as VtxoChain;
                    }) as unknown as RestIndexerProvider["getVtxoChain"],
                } as unknown as Partial<RestIndexerProvider>),
        },
        {
            name: "4. Provider unreachable",
            description:
                "Indexer fails every call — caught as NETWORK errors[]",
            expectedCatch: "indexer.getVtxoChain-failed",
            mutate: () =>
                new RestIndexerProvider(
                    "http://localhost:6199"
                ) as unknown as RestIndexerProvider,
        },
    ];

    const results = [] as Array<{
        attack: string;
        caught: boolean;
        catcher: string | null;
    }>;
    for (const a of attacks) {
        const out = await runAttack(a, baseIndexer, onchain, vtxo);
        results.push({
            attack: a.name,
            caught: out.caught,
            catcher: out.catcher,
        });
    }

    header("Summary");
    let pass = 0;
    for (const r of results) {
        const mark = r.caught ? "\x1b[32m✓\x1b[0m" : "\x1b[31m✗\x1b[0m";
        console.log(
            `  ${mark} ${r.attack} — caught by: ${r.catcher ?? "(NOT CAUGHT)"}`
        );
        if (r.caught) pass++;
    }
    console.log(`\n${pass}/${results.length} attacks caught.`);
    if (pass !== results.length) {
        process.exitCode = 1;
    }
}

main().catch((e) => {
    console.error("\x1b[1;31mFATAL:\x1b[0m", e);
    process.exitCode = 1;
});
