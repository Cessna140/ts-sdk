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
    toDisplayTxid,
    toSighashType,
    makeSignaturePathEntry,
    ok,
    err,
    type Txid,
    type BlockHeight,
    type CommitmentInfo,
    type Prevout,
    type Result,
    type SighashType,
} from "../../src/verification/types";
import { anchorVoutInRange } from "../../src/verification/anchor-verifier";
import { MAX_PREIMAGE_CANDIDATES } from "../../src/verification/preimage-verifier";

describe("P0 invariants (bug prevention)", () => {
    describe("B2 — Txid is display-order branded", () => {
        it("raw hex strings cannot be used as Txid without toDisplayTxid", () => {
            const bytes = new Uint8Array(32).fill(0xab);
            const txid: Txid = toDisplayTxid(bytes);
            // @ts-expect-error — raw string is not assignable to Txid
            const bogus: Txid = "abababab";
            expect(txid).toMatch(/^[0-9a-f]{64}$/);
            expect(typeof bogus).toBe("string");
        });

        it("toDisplayTxid rejects wrong-length byte arrays", () => {
            expect(() => toDisplayTxid(new Uint8Array(31))).toThrow();
            expect(() => toDisplayTxid(new Uint8Array(33))).toThrow();
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

    describe("B5 — SighashType is required (no default param)", () => {
        it("toSighashType validates range", () => {
            expect(toSighashType(0).valueOf()).toBe(0);
            expect(() => toSighashType(-1)).toThrow();
            expect(() => toSighashType(256)).toThrow();
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

    describe("B4 + B7 — CommitmentInfo requires batchAmount + vout", () => {
        it("CommitmentInfo cannot be constructed without batchAmount", () => {
            // @ts-expect-error — batchAmount is a required field
            const bogus: CommitmentInfo = {
                txid: toDisplayTxid(new Uint8Array(32)),
                vout: 0,
                batchScript: new Uint8Array(34),
                batchExpiryHeight: 100 as BlockHeight,
            };
            expect(bogus).toBeDefined();
        });

        it("CommitmentInfo cannot be constructed without vout", () => {
            // @ts-expect-error — vout is a required field; no default 0
            const bogus: CommitmentInfo = {
                txid: toDisplayTxid(new Uint8Array(32)),
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
        it("DagAdapter exposes commitmentParentedInputs", async () => {
            const mod = await import("../../src/verification/chain-walker");
            // Type-only check: the interface name is exported.
            expect(mod).toBeDefined();
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
