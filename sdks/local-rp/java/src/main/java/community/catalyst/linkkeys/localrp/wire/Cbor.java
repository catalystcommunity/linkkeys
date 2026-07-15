package community.catalyst.linkkeys.localrp.wire;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Hand-written minimal canonical CBOR (RFC 8949) codec.
 *
 * <p><b>This package is hand-written, pending a csilgen Java target.</b> No
 * csilgen generator emits Java types or codecs today (see the csilgen
 * request filed alongside this SDK, {@code
 * ~/repos/catalystcommunity/csilgen/docs/csilgen-requests/}); everything in
 * {@code community.catalyst.linkkeys.localrp.wire} hand-reproduces exactly
 * the wire structures the DNS-less local-RP protocol needs, verified
 * byte-for-byte against {@code sdks/local-rp/conformance/} — the same
 * approach the Go and TypeScript reference SDKs took before a generated
 * client existed for them (see those SDKs' {@code cbor.go} /
 * {@code vendor/csilgen-transport/cbor.ts}).
 *
 * <p>Only the subset CSIL-RPC and this protocol's structures need is
 * implemented: unsigned/negative integers, byte strings, text strings,
 * arrays, maps, and tags. Maps are emitted with RFC 8949 &sect;4.2.1 core
 * deterministic encoding &mdash; entries sorted by the bytewise lexicographic
 * order of their <em>encoded</em> keys &mdash; exactly mirroring the Rust
 * reference's generated codec (which bakes this same order in at
 * codegen time) and the TypeScript SDK's vendored {@code canonMap}. Sorting
 * at encode time (rather than hand-ordering every struct's fields, as the Go
 * generator does) means this codec only has to get the *sort rule* right
 * once, rather than getting struct-by-struct field order right by hand.
 *
 * <p>Indefinite-length items are rejected on decode (this protocol never
 * uses them); decoding a value also rejects trailing bytes, since a wire
 * envelope is always exactly one CBOR data item.
 */
public final class Cbor {
    private Cbor() {}

    /** The CBOR value model. */
    public sealed interface Value
            permits VInt, VBytes, VText, VArray, VMap, VTag, VBool, VNull {}

    public record VInt(long value) implements Value {}

    public record VBytes(byte[] value) implements Value {}

    public record VText(String value) implements Value {}

    public record VArray(List<Value> items) implements Value {}

    /** A map entry. Order in the source list is irrelevant: {@link #encode} always sorts. */
    public record Entry(Value key, Value value) {}

    public record VMap(List<Entry> entries) implements Value {}

    public record VTag(long tag, Value value) implements Value {}

    public record VBool(boolean value) implements Value {}

    public record VNull() implements Value {}

    private static final VNull NULL = new VNull();

    public static Value vint(long v) {
        return new VInt(v);
    }

    public static Value vbytes(byte[] v) {
        return new VBytes(v);
    }

    public static Value vtext(String v) {
        return new VText(v);
    }

    public static Value varray(List<Value> v) {
        return new VArray(v);
    }

    public static Value vmap(List<Entry> v) {
        return new VMap(v);
    }

    public static Value vtag(long tag, Value v) {
        return new VTag(tag, v);
    }

    public static Value vbool(boolean v) {
        return new VBool(v);
    }

    public static Value vnull() {
        return NULL;
    }

    /** A map entry keyed by a CBOR text string &mdash; the only key shape this protocol uses. */
    public static Entry entry(String key, Value value) {
        return new Entry(vtext(key), value);
    }

    /**
     * Build a definite-length CBOR array (major type 4) of pre-built items,
     * in order &mdash; the wire shape of every domain-separated "tuple" this
     * SDK needs to reproduce for house constructions that predate CSIL's
     * envelope pattern (revocation certificates, claim signatures, key
     * vouches: a fixed-arity array built from a Rust tuple via
     * {@code ciborium::ser::into_writer}, never a map). Order is significant
     * here (unlike {@link #vmap}, which always sorts) because these are
     * positional tuples, not maps.
     */
    public static Value tuple(Value... items) {
        List<Value> list = new ArrayList<>(items.length);
        for (Value item : items) {
            list.add(item);
        }
        return varray(list);
    }

    /**
     * {@code Option<&str>} encoded positionally within a {@link #tuple}:
     * {@code Some(s)} as a text string, {@code None} (Java {@code null}) as
     * CBOR null &mdash; matching how serde/ciborium serializes an
     * {@code Option} field inside a tuple. Do not confuse with
     * {@link #putOptText}, which OMITS the map key entirely for CSIL map
     * structures; a positional tuple cannot omit a slot without shifting
     * every later field, so it uses an explicit null placeholder instead.
     */
    public static Value optTextItem(String s) {
        return s == null ? vnull() : vtext(s);
    }

    /** Convenience: {@code entry(key, value)} only if {@code value} is non-null, else nothing. */
    public static void putIfPresent(List<Entry> entries, String key, Value value) {
        if (value != null) {
            entries.add(entry(key, value));
        }
    }

    public static void putText(List<Entry> entries, String key, String value) {
        entries.add(entry(key, vtext(value)));
    }

    public static void putOptText(List<Entry> entries, String key, String value) {
        if (value != null) {
            entries.add(entry(key, vtext(value)));
        }
    }

    public static void putBytes(List<Entry> entries, String key, byte[] value) {
        entries.add(entry(key, vbytes(value)));
    }

    public static void putOptBytes(List<Entry> entries, String key, byte[] value) {
        if (value != null) {
            entries.add(entry(key, vbytes(value)));
        }
    }

    public static void putBool(List<Entry> entries, String key, boolean value) {
        entries.add(entry(key, vbool(value)));
    }

    public static void putOptBool(List<Entry> entries, String key, Boolean value) {
        if (value != null) {
            entries.add(entry(key, vbool(value)));
        }
    }

    // -----------------------------------------------------------------
    // Encoding
    // -----------------------------------------------------------------

    public static byte[] encode(Value v) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeValue(v, out);
        return out.toByteArray();
    }

    private static void writeHead(ByteArrayOutputStream out, int major, long n) {
        int mt = (major & 0x7) << 5;
        if (n < 0) {
            throw new IllegalArgumentException("negative CBOR length/argument: " + n);
        }
        if (n < 24) {
            out.write(mt | (int) n);
        } else if (n <= 0xffL) {
            out.write(mt | 24);
            out.write((int) n);
        } else if (n <= 0xffffL) {
            out.write(mt | 25);
            out.write((int) (n >>> 8));
            out.write((int) n);
        } else if (n <= 0xffffffffL) {
            out.write(mt | 26);
            out.write((int) (n >>> 24));
            out.write((int) (n >>> 16));
            out.write((int) (n >>> 8));
            out.write((int) n);
        } else {
            out.write(mt | 27);
            for (int shift = 56; shift >= 0; shift -= 8) {
                out.write((int) (n >>> shift));
            }
        }
    }

    private static void writeValue(Value v, ByteArrayOutputStream out) {
        if (v instanceof VInt i) {
            if (i.value() >= 0) {
                writeHead(out, 0, i.value());
            } else {
                writeHead(out, 1, -1L - i.value());
            }
        } else if (v instanceof VBytes b) {
            writeHead(out, 2, b.value().length);
            out.writeBytes(b.value());
        } else if (v instanceof VText t) {
            byte[] utf8 = t.value().getBytes(StandardCharsets.UTF_8);
            writeHead(out, 3, utf8.length);
            out.writeBytes(utf8);
        } else if (v instanceof VArray a) {
            writeHead(out, 4, a.items().size());
            for (Value item : a.items()) {
                writeValue(item, out);
            }
        } else if (v instanceof VMap m) {
            writeCanonicalMap(m, out);
        } else if (v instanceof VTag tg) {
            writeHead(out, 6, tg.tag());
            writeValue(tg.value(), out);
        } else if (v instanceof VBool bo) {
            out.write(bo.value() ? 0xf5 : 0xf4);
        } else if (v instanceof VNull) {
            out.write(0xf6);
        } else {
            throw new IllegalStateException("unhandled CBOR value type: " + v);
        }
    }

    private static void writeCanonicalMap(VMap m, ByteArrayOutputStream out) {
        List<byte[]> keyBytes = new ArrayList<>(m.entries().size());
        List<byte[]> valBytes = new ArrayList<>(m.entries().size());
        for (Entry e : m.entries()) {
            keyBytes.add(encode(e.key()));
            valBytes.add(encode(e.value()));
        }
        Integer[] order = new Integer[m.entries().size()];
        for (int i = 0; i < order.length; i++) {
            order[i] = i;
        }
        Arrays.sort(order, (x, y) -> compareBytes(keyBytes.get(x), keyBytes.get(y)));

        writeHead(out, 5, m.entries().size());
        for (int idx : order) {
            out.writeBytes(keyBytes.get(idx));
            out.writeBytes(valBytes.get(idx));
        }
    }

    /**
     * Bytewise unsigned lexicographic comparison; a shorter run that is a
     * prefix of the longer sorts first &mdash; RFC 8949 &sect;4.2.1's rule,
     * matching Rust {@code Vec<u8>::cmp} / the TypeScript SDK's
     * {@code compareBytes}.
     */
    static int compareBytes(byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        for (int i = 0; i < n; i++) {
            int ai = a[i] & 0xff;
            int bi = b[i] & 0xff;
            if (ai != bi) {
                return ai - bi;
            }
        }
        return a.length - b.length;
    }

    // -----------------------------------------------------------------
    // Decoding
    // -----------------------------------------------------------------

    public static final class CborDecodeException extends RuntimeException {
        public CborDecodeException(String message) {
            super(message);
        }
    }

    /**
     * Decode a single CBOR data item from {@code data}. An envelope is
     * always exactly one self-contained CBOR item, so trailing bytes are
     * rejected rather than silently ignored.
     */
    public static Value decode(byte[] data) {
        Reader r = new Reader(data);
        Value v = r.readValue();
        if (r.pos != data.length) {
            throw new CborDecodeException(
                    "trailing bytes after CBOR item: " + (data.length - r.pos) + " byte(s)");
        }
        return v;
    }

    private static final class Reader {
        private final byte[] data;
        private int pos = 0;

        Reader(byte[] data) {
            this.data = data;
        }

        private int readByteUnsigned() {
            if (pos >= data.length) {
                throw new CborDecodeException("unexpected end of CBOR input");
            }
            return data[pos++] & 0xff;
        }

        private byte[] take(long n) {
            if (n < 0 || n > Integer.MAX_VALUE - 8) {
                throw new CborDecodeException("CBOR length out of range: " + n);
            }
            int len = (int) n;
            if (pos + len > data.length || pos + len < pos) {
                throw new CborDecodeException("unexpected end of CBOR input");
            }
            byte[] out = Arrays.copyOfRange(data, pos, pos + len);
            pos += len;
            return out;
        }

        private long readArgument(int ai) {
            if (ai < 24) {
                return ai;
            }
            switch (ai) {
                case 24:
                    return readByteUnsigned();
                case 25:
                    return (long) readByteUnsigned() << 8 | readByteUnsigned();
                case 26: {
                    long v = 0;
                    for (int i = 0; i < 4; i++) {
                        v = (v << 8) | readByteUnsigned();
                    }
                    return v;
                }
                case 27: {
                    long v = 0;
                    for (int i = 0; i < 8; i++) {
                        v = (v << 8) | readByteUnsigned();
                    }
                    return v;
                }
                default:
                    throw new CborDecodeException(
                            "unsupported CBOR additional info " + ai + " (indefinite lengths are not allowed)");
            }
        }

        Value readValue() {
            int head = readByteUnsigned();
            int major = head >>> 5;
            int ai = head & 0x1f;
            switch (major) {
                case 0:
                    return vint(readArgument(ai));
                case 1:
                    return vint(-1L - readArgument(ai));
                case 2:
                    return vbytes(take(readArgument(ai)));
                case 3:
                    return vtext(new String(take(readArgument(ai)), StandardCharsets.UTF_8));
                case 4: {
                    long n = readArgument(ai);
                    List<Value> items = new ArrayList<>();
                    for (long i = 0; i < n; i++) {
                        items.add(readValue());
                    }
                    return varray(items);
                }
                case 5: {
                    long n = readArgument(ai);
                    List<Entry> entries = new ArrayList<>();
                    for (long i = 0; i < n; i++) {
                        Value k = readValue();
                        Value v = readValue();
                        entries.add(new Entry(k, v));
                    }
                    return vmap(entries);
                }
                case 6:
                    return vtag(readArgument(ai), readValue());
                case 7:
                    if (ai == 20) {
                        return vbool(false);
                    }
                    if (ai == 21) {
                        return vbool(true);
                    }
                    if (ai == 22) {
                        return vnull();
                    }
                    throw new CborDecodeException("unsupported CBOR simple value with ai=" + ai);
                default:
                    throw new CborDecodeException("unsupported CBOR major type " + major);
            }
        }
    }

    // -----------------------------------------------------------------
    // Map navigation helpers (decode side)
    // -----------------------------------------------------------------

    public static Value mapGet(Value map, String key) {
        if (!(map instanceof VMap m)) {
            return null;
        }
        for (Entry e : m.entries()) {
            if (e.key() instanceof VText t && t.value().equals(key)) {
                return e.value();
            }
        }
        return null;
    }

    public static Value require(Value map, String key) {
        Value v = mapGet(map, key);
        if (v == null) {
            throw new CborDecodeException("missing required field '" + key + "'");
        }
        return v;
    }

    public static String asText(Value v) {
        if (v instanceof VText t) {
            return t.value();
        }
        throw new CborDecodeException("expected a CBOR text string, got " + describe(v));
    }

    public static byte[] asBytes(Value v) {
        if (v instanceof VBytes b) {
            return b.value();
        }
        throw new CborDecodeException("expected a CBOR byte string, got " + describe(v));
    }

    public static boolean asBool(Value v) {
        if (v instanceof VBool b) {
            return b.value();
        }
        throw new CborDecodeException("expected a CBOR bool, got " + describe(v));
    }

    public static long asInt(Value v) {
        if (v instanceof VInt i) {
            return i.value();
        }
        throw new CborDecodeException("expected a CBOR integer, got " + describe(v));
    }

    public static List<Value> asArray(Value v) {
        if (v instanceof VArray a) {
            return a.items();
        }
        throw new CborDecodeException("expected a CBOR array, got " + describe(v));
    }

    public static String requireText(Value map, String key) {
        return asText(require(map, key));
    }

    public static byte[] requireBytes(Value map, String key) {
        return asBytes(require(map, key));
    }

    public static String optText(Value map, String key) {
        Value v = mapGet(map, key);
        return v == null ? null : asText(v);
    }

    public static byte[] optBytes(Value map, String key) {
        Value v = mapGet(map, key);
        return v == null ? null : asBytes(v);
    }

    public static Boolean optBool(Value map, String key) {
        Value v = mapGet(map, key);
        return v == null ? null : asBool(v);
    }

    private static String describe(Value v) {
        return v == null ? "<absent>" : v.getClass().getSimpleName();
    }
}
