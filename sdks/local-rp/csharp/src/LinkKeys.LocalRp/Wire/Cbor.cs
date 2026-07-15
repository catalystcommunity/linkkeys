using System.Text;

namespace LinkKeys.LocalRp.Wire;

/// <summary>
/// Hand-written minimal canonical CBOR (RFC 8949) codec.
///
/// <para><b>This namespace is hand-written, pending a csilgen C# target.</b> No
/// csilgen generator emits C# types or codecs today (see the filed request,
/// <c>~/repos/catalystcommunity/csilgen/docs/csilgen-requests/csharp-target-does-not-exist.md</c>);
/// everything in <c>LinkKeys.LocalRp.Wire</c> hand-reproduces exactly the wire
/// structures the DNS-less local-RP protocol needs, verified byte-for-byte
/// against <c>sdks/local-rp/conformance/</c> — the same approach the
/// Go/TypeScript/Java reference SDKs took before a generated client existed
/// for them.</para>
///
/// <para>Only the subset CSIL-RPC and this protocol's structures need is
/// implemented: unsigned/negative integers, byte strings, text strings,
/// arrays, maps, and tags. Maps are emitted with RFC 8949 §4.2.1 core
/// deterministic encoding — entries sorted by the bytewise lexicographic
/// order of their <em>encoded</em> keys — exactly mirroring the Java SDK's
/// <c>wire/Cbor.java</c> (which sorts at encode time rather than requiring
/// each hand-written type's field-declaration order to already match
/// canonical order).</para>
///
/// <para>Indefinite-length items are rejected on decode (this protocol never
/// uses them); decoding a value also rejects trailing bytes, since a wire
/// envelope is always exactly one CBOR data item.</para>
/// </summary>
public static class Cbor
{
    /// <summary>The CBOR value model.</summary>
    public abstract record Value;

    public sealed record VInt(long Value) : Value;

    public sealed record VBytes(byte[] Value) : Value;

    public sealed record VText(string Value) : Value;

    public sealed record VArray(IReadOnlyList<Value> Items) : Value;

    /// <summary>A map entry. Order in the source list is irrelevant: <see cref="Encode"/> always sorts.</summary>
    public sealed record Entry(Value Key, Value Value);

    public sealed record VMap(IReadOnlyList<Entry> Entries) : Value;

    public sealed record VTag(long Tag, Value Value) : Value;

    public sealed record VBool(bool Value) : Value;

    public sealed record VNull : Value;

    private static readonly VNull NullValue = new();

    public static Value VInteger(long v) => new VInt(v);

    public static Value VBytesOf(byte[] v) => new VBytes(v);

    public static Value VTextOf(string v) => new VText(v);

    public static Value VArrayOf(IReadOnlyList<Value> v) => new VArray(v);

    public static Value VMapOf(IReadOnlyList<Entry> v) => new VMap(v);

    public static Value VTagOf(long tag, Value v) => new VTag(tag, v);

    public static Value VBoolOf(bool v) => new VBool(v);

    public static Value VNullValue() => NullValue;

    /// <summary>A map entry keyed by a CBOR text string — the only key shape this protocol uses.</summary>
    public static Entry EntryOf(string key, Value value) => new(VTextOf(key), value);

    /// <summary>
    /// Build a definite-length CBOR array (major type 4) of pre-built items, in order — the
    /// wire shape of every domain-separated "tuple" this SDK needs to reproduce for house
    /// constructions that predate CSIL's envelope pattern (revocation certificates, claim
    /// signatures, key vouches). Order is significant here (unlike <see cref="VMapOf"/>,
    /// which always sorts) because these are positional tuples, not maps.
    /// </summary>
    public static Value Tuple(params Value[] items) => VArrayOf(items);

    /// <summary>
    /// <c>Option&lt;&amp;str&gt;</c> encoded positionally within a <see cref="Tuple"/>:
    /// <c>Some(s)</c> as a text string, <c>None</c> (C# <c>null</c>) as CBOR null — matching
    /// how serde/ciborium serializes an <c>Option</c> field inside a tuple.
    /// </summary>
    public static Value OptTextItem(string? s) => s is null ? VNullValue() : VTextOf(s);

    public static void PutIfPresent(List<Entry> entries, string key, Value? value)
    {
        if (value is not null)
        {
            entries.Add(EntryOf(key, value));
        }
    }

    public static void PutText(List<Entry> entries, string key, string value) => entries.Add(EntryOf(key, VTextOf(value)));

    public static void PutOptText(List<Entry> entries, string key, string? value)
    {
        if (value is not null)
        {
            entries.Add(EntryOf(key, VTextOf(value)));
        }
    }

    public static void PutBytes(List<Entry> entries, string key, byte[] value) => entries.Add(EntryOf(key, VBytesOf(value)));

    public static void PutOptBytes(List<Entry> entries, string key, byte[]? value)
    {
        if (value is not null)
        {
            entries.Add(EntryOf(key, VBytesOf(value)));
        }
    }

    public static void PutBool(List<Entry> entries, string key, bool value) => entries.Add(EntryOf(key, VBoolOf(value)));

    public static void PutOptBool(List<Entry> entries, string key, bool? value)
    {
        if (value is not null)
        {
            entries.Add(EntryOf(key, VBoolOf(value.Value)));
        }
    }

    // -----------------------------------------------------------------
    // Encoding
    // -----------------------------------------------------------------

    public static byte[] Encode(Value v)
    {
        var stream = new MemoryStream();
        WriteValue(v, stream);
        return stream.ToArray();
    }

    private static void WriteHead(MemoryStream stream, int major, ulong n)
    {
        int mt = (major & 0x7) << 5;
        if (n < 24)
        {
            stream.WriteByte((byte)(mt | (int)n));
        }
        else if (n <= 0xff)
        {
            stream.WriteByte((byte)(mt | 24));
            stream.WriteByte((byte)n);
        }
        else if (n <= 0xffff)
        {
            stream.WriteByte((byte)(mt | 25));
            stream.WriteByte((byte)(n >> 8));
            stream.WriteByte((byte)n);
        }
        else if (n <= 0xffffffffL)
        {
            stream.WriteByte((byte)(mt | 26));
            stream.WriteByte((byte)(n >> 24));
            stream.WriteByte((byte)(n >> 16));
            stream.WriteByte((byte)(n >> 8));
            stream.WriteByte((byte)n);
        }
        else
        {
            stream.WriteByte((byte)(mt | 27));
            for (int shift = 56; shift >= 0; shift -= 8)
            {
                stream.WriteByte((byte)(n >> shift));
            }
        }
    }

    private static void WriteValue(Value v, MemoryStream stream)
    {
        switch (v)
        {
            case VInt i:
                if (i.Value >= 0)
                {
                    WriteHead(stream, 0, (ulong)i.Value);
                }
                else
                {
                    WriteHead(stream, 1, (ulong)(-1L - i.Value));
                }

                break;
            case VBytes b:
                WriteHead(stream, 2, (ulong)b.Value.Length);
                stream.Write(b.Value);
                break;
            case VText t:
                byte[] utf8 = System.Text.Encoding.UTF8.GetBytes(t.Value);
                WriteHead(stream, 3, (ulong)utf8.Length);
                stream.Write(utf8);
                break;
            case VArray a:
                WriteHead(stream, 4, (ulong)a.Items.Count);
                foreach (var item in a.Items)
                {
                    WriteValue(item, stream);
                }

                break;
            case VMap m:
                WriteCanonicalMap(m, stream);
                break;
            case VTag tg:
                WriteHead(stream, 6, (ulong)tg.Tag);
                WriteValue(tg.Value, stream);
                break;
            case VBool bo:
                stream.WriteByte(bo.Value ? (byte)0xf5 : (byte)0xf4);
                break;
            case VNull:
                stream.WriteByte(0xf6);
                break;
            default:
                throw new InvalidOperationException($"unhandled CBOR value type: {v}");
        }
    }

    private static void WriteCanonicalMap(VMap m, MemoryStream stream)
    {
        var keyBytes = new byte[m.Entries.Count][];
        var valBytes = new byte[m.Entries.Count][];
        for (int i = 0; i < m.Entries.Count; i++)
        {
            keyBytes[i] = Encode(m.Entries[i].Key);
            valBytes[i] = Encode(m.Entries[i].Value);
        }

        var order = Enumerable.Range(0, m.Entries.Count).ToArray();
        Array.Sort(order, (x, y) => CompareBytes(keyBytes[x], keyBytes[y]));

        WriteHead(stream, 5, (ulong)m.Entries.Count);
        foreach (var idx in order)
        {
            stream.Write(keyBytes[idx]);
            stream.Write(valBytes[idx]);
        }
    }

    /// <summary>
    /// Bytewise unsigned lexicographic comparison; a shorter run that is a prefix of the
    /// longer sorts first — RFC 8949 §4.2.1's rule.
    /// </summary>
    internal static int CompareBytes(byte[] a, byte[] b)
    {
        int n = Math.Min(a.Length, b.Length);
        for (int i = 0; i < n; i++)
        {
            int ai = a[i];
            int bi = b[i];
            if (ai != bi)
            {
                return ai - bi;
            }
        }

        return a.Length - b.Length;
    }

    // -----------------------------------------------------------------
    // Decoding
    // -----------------------------------------------------------------

    public sealed class CborDecodeException(string message) : Exception(message);

    /// <summary>
    /// Decode a single CBOR data item from <paramref name="data"/>. An envelope is always
    /// exactly one self-contained CBOR item, so trailing bytes are rejected rather than
    /// silently ignored.
    /// </summary>
    public static Value Decode(byte[] data)
    {
        var r = new Reader(data);
        var v = r.ReadValue();
        if (r.Pos != data.Length)
        {
            throw new CborDecodeException($"trailing bytes after CBOR item: {data.Length - r.Pos} byte(s)");
        }

        return v;
    }

    private sealed class Reader(byte[] data)
    {
        public int Pos;

        private int ReadByteUnsigned()
        {
            if (Pos >= data.Length)
            {
                throw new CborDecodeException("unexpected end of CBOR input");
            }

            return data[Pos++];
        }

        private byte[] Take(long n)
        {
            if (n < 0 || n > int.MaxValue - 8)
            {
                throw new CborDecodeException($"CBOR length out of range: {n}");
            }

            int len = (int)n;
            if (Pos + len > data.Length || Pos + len < Pos)
            {
                throw new CborDecodeException("unexpected end of CBOR input");
            }

            var outBytes = new byte[len];
            Array.Copy(data, Pos, outBytes, 0, len);
            Pos += len;
            return outBytes;
        }

        private long ReadArgument(int ai)
        {
            if (ai < 24)
            {
                return ai;
            }

            switch (ai)
            {
                case 24:
                    return ReadByteUnsigned();
                case 25:
                    return ((long)ReadByteUnsigned() << 8) | (uint)ReadByteUnsigned();
                case 26:
                {
                    long v = 0;
                    for (int i = 0; i < 4; i++)
                    {
                        v = (v << 8) | (uint)ReadByteUnsigned();
                    }

                    return v;
                }

                case 27:
                {
                    long v = 0;
                    for (int i = 0; i < 8; i++)
                    {
                        v = (v << 8) | (uint)ReadByteUnsigned();
                    }

                    return v;
                }

                default:
                    throw new CborDecodeException(
                        $"unsupported CBOR additional info {ai} (indefinite lengths are not allowed)");
            }
        }

        public Value ReadValue()
        {
            int head = ReadByteUnsigned();
            int major = head >> 5;
            int ai = head & 0x1f;
            switch (major)
            {
                case 0:
                    return VInteger(ReadArgument(ai));
                case 1:
                    return VInteger(-1L - ReadArgument(ai));
                case 2:
                    return VBytesOf(Take(ReadArgument(ai)));
                case 3:
                    return VTextOf(System.Text.Encoding.UTF8.GetString(Take(ReadArgument(ai))));
                case 4:
                {
                    long n = ReadArgument(ai);
                    var items = new List<Value>();
                    for (long i = 0; i < n; i++)
                    {
                        items.Add(ReadValue());
                    }

                    return VArrayOf(items);
                }

                case 5:
                {
                    long n = ReadArgument(ai);
                    var entries = new List<Entry>();
                    for (long i = 0; i < n; i++)
                    {
                        var k = ReadValue();
                        var v = ReadValue();
                        entries.Add(new Entry(k, v));
                    }

                    return VMapOf(entries);
                }

                case 6:
                    return VTagOf(ReadArgument(ai), ReadValue());
                case 7:
                    if (ai == 20)
                    {
                        return VBoolOf(false);
                    }

                    if (ai == 21)
                    {
                        return VBoolOf(true);
                    }

                    if (ai == 22)
                    {
                        return VNullValue();
                    }

                    throw new CborDecodeException($"unsupported CBOR simple value with ai={ai}");
                default:
                    throw new CborDecodeException($"unsupported CBOR major type {major}");
            }
        }
    }

    // -----------------------------------------------------------------
    // Map navigation helpers (decode side)
    // -----------------------------------------------------------------

    public static Value? MapGet(Value map, string key)
    {
        if (map is not VMap m)
        {
            return null;
        }

        foreach (var e in m.Entries)
        {
            if (e.Key is VText t && t.Value == key)
            {
                return e.Value;
            }
        }

        return null;
    }

    public static Value Require(Value map, string key) =>
        MapGet(map, key) ?? throw new CborDecodeException($"missing required field '{key}'");

    public static string AsText(Value v) => v switch
    {
        VText t => t.Value,
        _ => throw new CborDecodeException($"expected a CBOR text string, got {Describe(v)}"),
    };

    public static byte[] AsBytes(Value v) => v switch
    {
        VBytes b => b.Value,
        _ => throw new CborDecodeException($"expected a CBOR byte string, got {Describe(v)}"),
    };

    public static bool AsBool(Value v) => v switch
    {
        VBool b => b.Value,
        _ => throw new CborDecodeException($"expected a CBOR bool, got {Describe(v)}"),
    };

    public static long AsInt(Value v) => v switch
    {
        VInt i => i.Value,
        _ => throw new CborDecodeException($"expected a CBOR integer, got {Describe(v)}"),
    };

    public static IReadOnlyList<Value> AsArray(Value v) => v switch
    {
        VArray a => a.Items,
        _ => throw new CborDecodeException($"expected a CBOR array, got {Describe(v)}"),
    };

    public static string RequireText(Value map, string key) => AsText(Require(map, key));

    public static byte[] RequireBytes(Value map, string key) => AsBytes(Require(map, key));

    public static string? OptText(Value map, string key)
    {
        var v = MapGet(map, key);
        return v is null ? null : AsText(v);
    }

    public static byte[]? OptBytes(Value map, string key)
    {
        var v = MapGet(map, key);
        return v is null ? null : AsBytes(v);
    }

    public static bool? OptBool(Value map, string key)
    {
        var v = MapGet(map, key);
        return v is null ? null : AsBool(v);
    }

    private static string Describe(Value? v) => v is null ? "<absent>" : v.GetType().Name;
}
