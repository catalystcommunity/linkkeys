using LinkKeys.LocalRp.Wire;

namespace LinkKeys.LocalRp.Rpc;

/// <summary>
/// CSIL-RPC request/response envelopes
/// (<c>~/repos/catalystcommunity/csilgen/docs/csil-rpc-transport.md</c>).
/// <b>Hand-written, pending a csilgen C# target</b> — no generated CSIL-RPC client
/// exists for C#, so this SDK hand-implements exactly the envelope shape every other
/// language's generated client also produces.
///
/// <para>Only the byte-stream (TCP/TLS) carrier framing is needed here: a 4-byte
/// big-endian length prefix followed by the CBOR envelope (see <see cref="StreamFraming"/>).</para>
/// </summary>
public static class RpcEnvelope
{
    public const int Version = 1;
    public const int TagEncodedCbor = 24;

    /// <summary>Transport status registry (subset this SDK observes). <c>0</c> = a typed reply is present.</summary>
    public static class Status
    {
        public const int Ok = 0;
        public const int MalformedEnvelope = 1;
        public const int UnknownServiceOrOp = 2;
        public const int Unauthenticated = 3;
        public const int Forbidden = 4;
        public const int VersionUnsupported = 5;
        public const int Internal = 6;
        public const int Unavailable = 7;
        public const int DeadlineExceeded = 8;
    }

    private static Cbor.Value Tag24(byte[] payload) => Cbor.VTagOf(TagEncodedCbor, Cbor.VBytesOf(payload));

    private static byte[] Untag24(Cbor.Value v)
    {
        if (v is Cbor.VTag { Value: Cbor.VBytes b } t && t.Tag == TagEncodedCbor)
        {
            return b.Value;
        }

        throw new SdkException(SdkException.ErrorKind.Protocol, "expected a tag-24 (encoded-cbor) payload");
    }

    private static void CheckVersion(long v)
    {
        if (v != Version)
        {
            throw new SdkException(SdkException.ErrorKind.Protocol, $"unsupported transport version {v}");
        }
    }

    /// <summary>A CSIL-RPC request (client → server).</summary>
    public sealed record Request(string Service, string Op, int? Id, byte[] Payload, string? Auth)
    {
        public Request(string service, string op, byte[] payload) : this(service, op, null, payload, null)
        {
        }

        public byte[] Encode()
        {
            var entries = new List<Cbor.Entry>();
            Cbor.PutText(entries, "service", Service);
            Cbor.PutText(entries, "op", Op);
            entries.Add(Cbor.EntryOf("v", Cbor.VInteger(Version)));
            entries.Add(Cbor.EntryOf("payload", Tag24(Payload)));
            if (Id is not null)
            {
                entries.Add(Cbor.EntryOf("id", Cbor.VInteger(Id.Value)));
            }

            Cbor.PutOptText(entries, "auth", Auth);
            return Cbor.Encode(Cbor.VMapOf(entries));
        }
    }

    public static Request DecodeRequest(byte[] bytes)
    {
        var v = Cbor.Decode(bytes);
        CheckVersion(Cbor.AsInt(Cbor.Require(v, "v")));
        var payload = Untag24(Cbor.Require(v, "payload"));
        var service = Cbor.RequireText(v, "service");
        var op = Cbor.RequireText(v, "op");
        var idField = Cbor.MapGet(v, "id");
        int? id = idField is null ? null : (int)Cbor.AsInt(idField);
        var auth = Cbor.OptText(v, "auth");
        return new Request(service, op, id, payload, auth);
    }

    /// <summary>A CSIL-RPC response (server → client).</summary>
    public sealed record Response(int? Id, int StatusCode, string? Variant, string? Error, byte[] Payload)
    {
        public static Response Ok(string variant, byte[] payload) => new(null, Status.Ok, variant, null, payload);

        public static Response TransportError(int status, string message) => new(null, status, null, message, []);

        public bool IsOk => StatusCode == Status.Ok;

        public byte[] Encode()
        {
            var entries = new List<Cbor.Entry> { Cbor.EntryOf("v", Cbor.VInteger(Version)), Cbor.EntryOf("status", Cbor.VInteger(StatusCode)) };
            entries.Add(Cbor.EntryOf("payload", Tag24(Payload)));
            if (Id is not null)
            {
                entries.Add(Cbor.EntryOf("id", Cbor.VInteger(Id.Value)));
            }

            Cbor.PutOptText(entries, "variant", Variant);
            Cbor.PutOptText(entries, "error", Error);
            return Cbor.Encode(Cbor.VMapOf(entries));
        }
    }

    public static Response DecodeResponse(byte[] bytes)
    {
        var v = Cbor.Decode(bytes);
        CheckVersion(Cbor.AsInt(Cbor.Require(v, "v")));
        var payloadField = Cbor.MapGet(v, "payload");
        var payload = payloadField is null ? [] : Untag24(payloadField);
        var status = (int)Cbor.AsInt(Cbor.Require(v, "status"));
        var idField = Cbor.MapGet(v, "id");
        int? id = idField is null ? null : (int)Cbor.AsInt(idField);
        var variant = Cbor.OptText(v, "variant");
        var error = Cbor.OptText(v, "error");
        return new Response(id, status, variant, error, payload);
    }
}
