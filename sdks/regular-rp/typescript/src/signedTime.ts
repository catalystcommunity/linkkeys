// Signed timestamps, mirroring `crates/liblinkkeys/src/timestamp.rs`'s
// `SignedTime`. A signed tuple payload carries a time as a CBOR integer of
// whole Unix seconds. A time with a fraction of a second was never signed, so
// it fails here. Do not round it: rounding would make a different time verify.

/** Thrown when a time cannot go into a signed payload. */
export class SignedTimeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SignedTimeError";
  }
}

/**
 * The whole Unix seconds of `t`. Throws `SignedTimeError` when `t` is not a
 * valid time or has a fraction of a second.
 *
 * A JavaScript `Date` holds milliseconds only. The generated codec drops a
 * fraction smaller than one millisecond when it decodes a time, so this check
 * cannot see that fraction.
 */
export function signedSeconds(t: Date): number {
  const ms = t.getTime();
  if (!Number.isFinite(ms)) throw new SignedTimeError("invalid time");
  if (ms % 1000 !== 0) throw new SignedTimeError("a signed timestamp must be a whole number of seconds");
  return ms / 1000;
}

/** `t` without its fraction of a second (rounded down), for a time that will be signed. */
export function wholeSeconds(t: Date): Date {
  return new Date(Math.floor(t.getTime() / 1000) * 1000);
}

/** The current time in whole seconds, for a timestamp that will be signed. */
export function nowWholeSeconds(): Date {
  return wholeSeconds(new Date());
}
