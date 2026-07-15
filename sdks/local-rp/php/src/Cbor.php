<?php

declare(strict_types=1);

namespace LinkKeys\LocalRp;

/**
 * A minimal, hand-written CBOR (RFC 8949) encoder/decoder covering exactly
 * the subset this SDK needs: unsigned/negative integers, byte strings, text
 * strings, definite-length arrays, definite-length maps (text-string keys),
 * tag 24 (encoded-CBOR), and the `true`/`false`/`null` simple values.
 *
 * Why hand-written rather than the csilgen-generated `src/Generated/codec.php`:
 * that generated codec has a confirmed bug (every list-typed field's
 * (de)serializer references an undefined `$var` instead of `$field`, so any
 * CSIL `[* T]` field silently encodes/decodes as an empty list — see the
 * csilgen defect filed at
 * `~/repos/catalystcommunity/csilgen/docs/csilgen-requests/`). Almost every
 * structure this protocol needs has a list field (`supported_suites`,
 * `requested_claims`, `signatures`, `keys`, `revocations`, `claims`), so the
 * generated codec is not usable as emitted. Per AGENTS.md, generated files
 * are never hand-edited — the fix belongs in csilgen. This module plus
 * `Wire.php` is this SDK's own correct (de)serialization for the wire
 * structures it actually uses, following the same envelope/signature
 * conventions as `crates/liblinkkeys/src/local_rp.rs`.
 *
 * PHP strings do not distinguish "text" from "bytes" the way CBOR does, so a
 * bare `string` value always encodes as a CBOR text string (major type 3).
 * Wrap raw byte values in {@see CborBytes} to force a CBOR byte string
 * (major type 2) instead — this matters for every `bytes`-typed CSIL field
 * (keys, signatures, nonces, ciphertexts, tickets).
 *
 * Map key order does not affect wire correctness here: every decoder on the
 * other end (this SDK's own decode, and the real IDP's `ciborium`-based
 * decode) looks fields up by name, not position. Keys are still emitted in
 * insertion order for determinism/readability, not because it is required.
 */
final class Cbor
{
    /** @param mixed $value */
    public static function encode($value): string
    {
        $out = '';
        self::encodeInto($out, $value);
        return $out;
    }

    /** @return mixed */
    public static function decode(string $bytes)
    {
        $pos = 0;
        $value = self::decodeAt($bytes, $pos);
        if ($pos !== strlen($bytes)) {
            throw new CborException('trailing bytes after CBOR item');
        }
        return $value;
    }

    /** Wrap raw bytes so they encode as a CBOR byte string (major type 2). */
    public static function bytes(string $raw): CborBytes
    {
        return new CborBytes($raw);
    }

    /**
     * Decode a top-level CBOR map like {@see self::decode}, but ALSO report
     * each entry's raw CBOR major type and exact raw byte span. {@see
     * self::decode} deliberately collapses byte strings (major type 2) and
     * text strings (major type 3) to the same plain PHP `string` — see this
     * class's docblock — which makes it structurally unable to reject a
     * field that must be one and not the other. `conformance/claims.json`'s
     * `claim_value_as_cbor_text_rejected` vector exists exactly to catch a
     * codec that cannot tell `Claim.claim_value` (a bstr) apart from a tstr;
     * {@see \LinkKeys\LocalRp\Wire::decodeClaim} uses this method to enforce
     * that distinction. The byte spans let a caller re-run a
     * stricter/element-specific decode (e.g. {@see
     * \LinkKeys\LocalRp\Wire::decodeClaim} again) against a nested value's
     * own exact bytes, via {@see self::decodeArraySpans}.
     *
     * @return array{0: array<string,mixed>, 1: array<string,int>, 2: array<string,string>}
     *   [decoded map (same shape as {@see self::decode}), key => CBOR major
     *   type of its value, key => raw encoded bytes of its value]
     */
    public static function decodeMapWithValueTypes(string $bytes): array
    {
        $pos = 0;
        self::need($bytes, $pos, 1);
        $initial = ord($bytes[$pos]);
        if (($initial >> 5) !== 5) {
            throw new CborException('expected a CBOR map at top level');
        }
        $pos++;
        $count = self::argument($bytes, $pos, $initial & 0x1f);

        $map = [];
        $types = [];
        $spans = [];
        for ($i = 0; $i < $count; $i++) {
            $key = self::decodeAt($bytes, $pos);
            self::need($bytes, $pos, 1);
            $valueMajor = ord($bytes[$pos]) >> 5;
            $valueStart = $pos;
            $value = self::decodeAt($bytes, $pos);
            $map[$key] = $value;
            $types[$key] = $valueMajor;
            $spans[$key] = substr($bytes, $valueStart, $pos - $valueStart);
        }
        if ($pos !== strlen($bytes)) {
            throw new CborException('trailing bytes after CBOR item');
        }
        return [$map, $types, $spans];
    }

    /**
     * Decode a top-level CBOR array into one raw byte span per element,
     * without interpreting each element's contents — see {@see
     * self::decodeMapWithValueTypes}.
     *
     * @return string[]
     */
    public static function decodeArraySpans(string $bytes): array
    {
        $pos = 0;
        self::need($bytes, $pos, 1);
        $initial = ord($bytes[$pos]);
        if (($initial >> 5) !== 4) {
            throw new CborException('expected a CBOR array at top level');
        }
        $pos++;
        $count = self::argument($bytes, $pos, $initial & 0x1f);

        $spans = [];
        for ($i = 0; $i < $count; $i++) {
            $start = $pos;
            self::decodeAt($bytes, $pos);
            $spans[] = substr($bytes, $start, $pos - $start);
        }
        if ($pos !== strlen($bytes)) {
            throw new CborException('trailing bytes after CBOR item');
        }
        return $spans;
    }

    public static function tag(int $tag, $value): CborTag
    {
        return new CborTag($tag, $value);
    }

    /**
     * Encode an associative array as a CBOR map (major type 5), even when
     * it is empty. Plain PHP arrays are ambiguous between "empty list" and
     * "empty map" (an empty `[]` looks list-shaped to {@see self::isList}),
     * which matters for every CSIL struct/request type: those always encode
     * as a map even with zero fields present (e.g. `EmptyRequest`, or
     * `GetRevocationsRequest` when its one optional field is absent) — see
     * `crates/liblinkkeys/src/generated/codec.gen.rs`'s
     * `csil_enc_empty_request`/`csil_enc_get_revocations_request`, both of
     * which always return `CsilCborValue::Map(...)`. Every top-level
     * struct/request encoder in {@see \LinkKeys\LocalRp\Wire} should go
     * through this method rather than the auto-detecting
     * {@see self::encode()}, so an accidentally-empty map is never
     * misencoded as an empty array.
     *
     * @param array<string,mixed> $assoc
     */
    public static function encodeMap(array $assoc): string
    {
        $out = '';
        self::head($out, 5, count($assoc));
        foreach ($assoc as $k => $v) {
            self::encodeInto($out, (string) $k);
            self::encodeInto($out, $v);
        }
        return $out;
    }

    /**
     * @param mixed $value
     */
    private static function encodeInto(string &$out, $value): void
    {
        if ($value instanceof CborBytes) {
            self::head($out, 2, strlen($value->data));
            $out .= $value->data;
        } elseif ($value instanceof CborTag) {
            self::head($out, 6, $value->tag);
            self::encodeInto($out, $value->value);
        } elseif (is_int($value)) {
            if ($value < 0) {
                self::head($out, 1, -1 - $value);
            } else {
                self::head($out, 0, $value);
            }
        } elseif (is_string($value)) {
            self::head($out, 3, strlen($value));
            $out .= $value;
        } elseif (is_bool($value)) {
            $out .= $value ? "\xf5" : "\xf4";
        } elseif ($value === null) {
            $out .= "\xf6";
        } elseif (is_array($value)) {
            if (self::isList($value)) {
                self::head($out, 4, count($value));
                foreach ($value as $item) {
                    self::encodeInto($out, $item);
                }
            } else {
                self::head($out, 5, count($value));
                foreach ($value as $k => $v) {
                    self::encodeInto($out, (string) $k);
                    self::encodeInto($out, $v);
                }
            }
        } else {
            throw new CborException('cannot encode value of type ' . get_debug_type($value));
        }
    }

    private static function head(string &$out, int $major, int $arg): void
    {
        $mt = $major << 5;
        if ($arg < 24) {
            $out .= chr($mt | $arg);
        } elseif ($arg < 0x100) {
            $out .= chr($mt | 24) . chr($arg);
        } elseif ($arg < 0x10000) {
            $out .= chr($mt | 25) . pack('n', $arg);
        } elseif ($arg < 0x100000000) {
            $out .= chr($mt | 26) . pack('N', $arg);
        } else {
            $hi = intdiv($arg, 0x100000000);
            $lo = $arg % 0x100000000;
            $out .= chr($mt | 27) . pack('NN', $hi, $lo);
        }
    }

    /** @return mixed */
    private static function decodeAt(string $bytes, int &$pos)
    {
        self::need($bytes, $pos, 1);
        $initial = ord($bytes[$pos++]);
        $major = $initial >> 5;
        $info = $initial & 0x1f;

        if ($major === 7) {
            return match ($info) {
                20 => false,
                21 => true,
                22 => null,
                default => throw new CborException("unsupported simple value (additional info {$info})"),
            };
        }

        $arg = self::argument($bytes, $pos, $info);
        switch ($major) {
            case 0:
                return $arg;
            case 1:
                return -1 - $arg;
            case 2:
            case 3:
                self::need($bytes, $pos, $arg);
                $s = substr($bytes, $pos, $arg);
                $pos += $arg;
                return $s;
            case 4:
                $items = [];
                for ($i = 0; $i < $arg; $i++) {
                    $items[] = self::decodeAt($bytes, $pos);
                }
                return $items;
            case 5:
                $map = [];
                for ($i = 0; $i < $arg; $i++) {
                    $key = self::decodeAt($bytes, $pos);
                    $map[$key] = self::decodeAt($bytes, $pos);
                }
                return $map;
            case 6:
                return new CborTag($arg, self::decodeAt($bytes, $pos));
            default:
                throw new CborException("unsupported CBOR major type {$major}");
        }
    }

    private static function argument(string $bytes, int &$pos, int $info): int
    {
        if ($info < 24) {
            return $info;
        }
        if ($info === 24) {
            self::need($bytes, $pos, 1);
            return ord($bytes[$pos++]);
        }
        if ($info === 25) {
            self::need($bytes, $pos, 2);
            $v = unpack('n', substr($bytes, $pos, 2))[1];
            $pos += 2;
            return $v;
        }
        if ($info === 26) {
            self::need($bytes, $pos, 4);
            $v = unpack('N', substr($bytes, $pos, 4))[1];
            $pos += 4;
            return $v;
        }
        if ($info === 27) {
            self::need($bytes, $pos, 8);
            $p = unpack('N2', substr($bytes, $pos, 8));
            $pos += 8;
            return (int) ($p[1] * 0x100000000 + $p[2]);
        }
        throw new CborException("unsupported additional-info value {$info}");
    }

    private static function need(string $bytes, int $pos, int $n): void
    {
        if ($pos + $n > strlen($bytes)) {
            throw new CborException('unexpected end of CBOR input');
        }
    }

    private static function isList(array $value): bool
    {
        $i = 0;
        foreach ($value as $k => $_) {
            if ($k !== $i) {
                return false;
            }
            $i++;
        }
        return true;
    }
}

final class CborTag
{
    public int $tag;
    /** @var mixed */
    public $value;

    /** @param mixed $value */
    public function __construct(int $tag, $value)
    {
        $this->tag = $tag;
        $this->value = $value;
    }
}

final class CborBytes
{
    public string $data;

    public function __construct(string $data)
    {
        $this->data = $data;
    }
}

final class CborException extends \RuntimeException
{
}
