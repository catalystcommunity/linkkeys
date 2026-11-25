// Timestamp helpers, mirroring `crates/liblinkkeys/src/timestamp.rs`'s
// subset this SDK needs.
//
// On the wire every CSIL time field is a `timestamp`: CBOR tag 0 wrapping
// RFC 3339 text in UTC. The generated codec maps that to a `Date`. Inside a
// signed TUPLE payload (claim, key revocation, key vouch), a timestamp is a
// CBOR integer of whole Unix seconds instead. A signed timestamp with a
// fraction of a second is refused, never rounded: the signer and every
// verifier must sign the same instant.

import { int, nullElem, type TupleElem } from "./cborTuple.ts";

export class TimestampError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TimestampError";
  }
}

/** True when `d` holds a real instant (not an `Invalid Date`). */
export function isValidDate(d: Date): boolean {
  return !Number.isNaN(d.getTime());
}

/** `d` without its fraction of a second (rounded down). */
export function wholeSeconds(d: Date): Date {
  const ms = d.getTime();
  if (Number.isNaN(ms)) throw new TimestampError("invalid time");
  return new Date(Math.floor(ms / 1000) * 1000);
}

/**
 * The signed form of `d`: whole Unix seconds. Throws `TimestampError` when
 * `d` is invalid or has a fraction of a second (`SignedTime::new`).
 */
export function signedSeconds(d: Date): number {
  const ms = d.getTime();
  if (Number.isNaN(ms)) throw new TimestampError("invalid time");
  if (ms % 1000 !== 0) {
    throw new TimestampError("a signed timestamp must be a whole number of seconds");
  }
  return ms / 1000;
}

/** A signed-tuple element for `d` (CBOR integer of whole Unix seconds). */
export function signedTime(d: Date): TupleElem {
  return int(signedSeconds(d));
}

/** `signedTime(d)`, or CBOR null when `d` is absent. */
export function signedTimeOrNull(d: Date | undefined | null): TupleElem {
  return d === undefined || d === null ? nullElem() : signedTime(d);
}
