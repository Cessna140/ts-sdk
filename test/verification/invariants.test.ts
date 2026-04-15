/**
 * P0 invariant smoke tests — one per v1 self-review bug.
 *
 * These tests use `// @ts-expect-error` to assert that the forbidden code
 * shapes from v1 CANNOT be written in v2. If any `@ts-expect-error`
 * comment is on a line TypeScript accepts, the test file fails to compile
 * — which is the entire point.
 *
 * Runtime assertions are kept to a minimum; the compile-time proof is
 * what matters here. Vitest still runs these so that CI surfaces
 * regressions.
 */

import { describe, expect, it } from "vitest";
import {
    txidFromDisplayBytes,
    txidFromInternalBytes,
    parseSighashFromSchnorrSig,
    sighashTypeDefault,
    makeSignaturePathEntry,
    ok,
    err,
    type Txid,
    type BlockHeight,
    type ResolvedCommitmentInfo,
    type Prevout,
    type Result,
    type SighashType,
} from "../../src/verification/types";
import { anchorVoutInRange } from "../../src/verification/anchor-verifier";
import { MAX_PREIMAGE_CANDIDATES } from "../../src/verification/preimage-verifier";
import { makeDagAdapter } from "../../src/verification/chain-walker";

describe("P0 invariants (bug prevention)", () => {
    describe("B2 — Txid is display-order branded with named constructors", () => {
        it("raw strings cannot be used as Txid", () => {
            const bytes = new Uint8Array(32).fill(0xab);
            const txid: Txid = txidFromDisplayBytes(bytes);
            // @ts-expect-error — raw string is not assignable to Txid
            const bogus: Txid = "abababab";
            expect(txid).toMatch(/^[0-9a-f]{64}$/);
            expect(typeof bogus).toBe("string");
        });

        it("txidFromInternalBytes reverses; txidFromDisplayBytes does not", () => {
            // Byte 0 = 0x01, byte 31 = 0x02, middle zeros.
            const bytes = new Uint8Array(32);
            bytes[0] = 0x01;
            bytes[31] = 0x02;
            expect(txidFromDisplayBytes(bytes)).toBe(
                "01" + "00".repeat(30) + "02"
            );
            expect(txidFromInternalBytes(bytes)).toBe(
                "02" + "00".repeat(30) + "01"
            );
        });

        it("both constructors reject wrong-length byte arrays", () => {
            expect(() => txidFromDisplayBytes(new Uint8Array(31))).toThrow();
            expect(() => txidFromInternalBytes(new Uint8Array(33))).toThrow();
        });
    });

    describe("B9 — BlockHeight is CLTV-parser branded", () => {
        it("raw numbers cannot be used as BlockHeight", () => {
            // @ts-expect-error — plain number not assignable to BlockHeight
            const bogus: BlockHeight = 12345;
            expect(bogus).toBe(12345);
        });

        it("no fromIsoTimestamp / fromDate constructor exists", async () => {
            const mod = await import("../../src/verification/types");
            for (const key of Object.keys(mod)) {
                expect(key).not.toMatch(
                    /fromIso|fromTimestamp|fromDate|approximate/i
                );
            }
        });
    });

    describe("B5 — SighashType only constructible from a real Schnorr sig", () => {
        it("parseSighashFromSchnorrSig: 64-byte sig → 0x00", () => {
            expect(parseSighashFromSchnorrSig(new Uint8Array(64))).toBe(0);
        });

        it("parseSighashFromSchnorrSig: 65-byte sig carries the sighash byte", () => {
            const sig = new Uint8Array(65);
            sig[64] = 0x81; // SIGHASH_ALL | ACP
            expect(parseSighashFromSchnorrSig(sig)).toBe(0x81);
        });

        it("parseSighashFromSchnorrSig: 65-byte sig with sighash=0x00 is rejected", () => {
            const sig = new Uint8Array(65); // byte 64 = 0x00
            expect(() => parseSighashFromSchnorrSig(sig)).toThrow(
                /64-byte form/
            );
        });

        it("parseSighashFromSchnorrSig rejects wrong-length", () => {
            expect(() =>
                parseSighashFromSchnorrSig(new Uint8Array(63))
            ).toThrow();
            expect(() =>
                parseSighashFromSchnorrSig(new Uint8Array(66))
            ).toThrow();
        });

        it("sighashTypeDefault is an opt-in labelled constant", () => {
            expect(sighashTypeDefault).toBe(0);
        });

        it("raw numbers cannot be used as SighashType", () => {
            // @ts-expect-error — plain number not assignable to SighashType
            const bogus: SighashType = 0;
            expect(bogus).toBe(0);
        });
    });

    describe("B1 — SignaturePathEntry requires non-empty perInputPrevouts", () => {
        it("empty prevouts array is rejected at construction", () => {
            const fakeTx = { inputsLength: 2 } as unknown as Parameters<
                typeof makeSignaturePathEntry
            >[0];
            expect(() => makeSignaturePathEntry(fakeTx, [])).toThrow(
                /must not be empty/
            );
        });

        it("prevouts.length must equal tx.inputsLength", () => {
            const fakeTx = { inputsLength: 2 } as unknown as Parameters<
                typeof makeSignaturePathEntry
            >[0];
            const one: Prevout = {
                script: new Uint8Array(34),
                amount: 1000n,
            };
            expect(() => makeSignaturePathEntry(fakeTx, [one])).toThrow(
                /prevouts.length/
            );
        });

        it("singular parentOutputScript field is not part of the type", () => {
            // @ts-expect-error — singular fields do not exist on SignaturePathEntry
            const bogus: import("../../src/verification/types").SignaturePathEntry =
                {
                    tx: {} as never,
                    parentOutputScript: new Uint8Array(34),
                    parentOutputAmount: 1000n,
                };
            expect(bogus).toBeDefined();
        });
    });

    describe("B4 + B7 — ResolvedCommitmentInfo requires every field", () => {
        it("ResolvedCommitmentInfo cannot be constructed without batchAmount", () => {
            // @ts-expect-error — batchAmount is a required field
            const bogus: ResolvedCommitmentInfo = {
                txid: txidFromDisplayBytes(new Uint8Array(32)),
                vout: 0,
                batchScript: new Uint8Array(34),
                batchExpiryHeight: 100 as BlockHeight,
            };
            expect(bogus).toBeDefined();
        });

        it("ResolvedCommitmentInfo cannot be constructed without vout", () => {
            // @ts-expect-error — vout is a required field; no default 0
            const bogus: ResolvedCommitmentInfo = {
                txid: txidFromDisplayBytes(new Uint8Array(32)),
                batchScript: new Uint8Array(34),
                batchAmount: 1000n,
                batchExpiryHeight: 100 as BlockHeight,
            };
            expect(bogus).toBeDefined();
        });
    });

    describe("B7 — Result type for fallible commitment resolution", () => {
        it("Result<T, E> forces callers to discriminate", () => {
            const success: Result<number, string> = ok(42);
            const failure: Result<number, string> = err("bad");
            if (success.ok) {
                // @ts-expect-error — .error not accessible on ok branch
                const _ = success.error;
                expect(success.value).toBe(42);
            }
            if (!failure.ok) {
                // @ts-expect-error — .value not accessible on err branch
                const _ = failure.value;
                expect(failure.error).toBe("bad");
            }
        });
    });

    describe("B6 — range-check functions return CheckResult, never throw", () => {
        it("anchorVoutInRange signature returns CheckResult", () => {
            const result = anchorVoutInRange(99, 2);
            expect(result).toHaveProperty("name");
            expect(result).toHaveProperty("passed");
            expect(typeof result.passed).toBe("boolean");
        });
    });

    describe("B8 — MAX_PREIMAGE_CANDIDATES cap is exported", () => {
        it("cap is 64 and is a compile-time const", () => {
            expect(MAX_PREIMAGE_CANDIDATES).toBe(64);
        });
    });

    describe("B3 + B10 — DAG iterator and per-path schedule APIs exist", () => {
        it("DagAdapter.commitmentParentedInputs is a real iterator factory", () => {
            expect(typeof makeDagAdapter).toBe("function");
            const emptyGraph = {
                nodes: new Map(),
                parents: new Map(),
                children: new Map(),
                roots: [],
            };
            const adapter = makeDagAdapter(emptyGraph);
            expect(typeof adapter.commitmentParentedInputs).toBe("function");
            expect(Array.from(adapter.commitmentParentedInputs())).toEqual([]);
        });

        it("scheduleFromDag is the only constructor path", async () => {
            const mod = await import("../../src/exit/bundle-builder");
            expect(mod).toHaveProperty("scheduleFromDag");
            // Forbidden v1 shape: global-offset constructor must not exist.
            for (const key of Object.keys(mod)) {
                expect(key).not.toMatch(/globalOffset|maxConfirmation/i);
            }
        });
    });
});
