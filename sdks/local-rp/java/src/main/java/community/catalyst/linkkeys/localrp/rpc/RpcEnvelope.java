package community.catalyst.linkkeys.localrp.rpc;

import java.util.ArrayList;
import java.util.List;

import community.catalyst.linkkeys.localrp.SdkException;
import community.catalyst.linkkeys.localrp.wire.Cbor;
import community.catalyst.linkkeys.localrp.wire.Cbor.Entry;
import community.catalyst.linkkeys.localrp.wire.Cbor.Value;

/**
 * CSIL-RPC request/response envelopes (`~/repos/catalystcommunity/csilgen/docs/csil-rpc-transport.md`).
 * <b>Hand-written, pending a csilgen Java target</b> &mdash; no generated
 * CSIL-RPC client exists for Java, so this SDK hand-implements exactly the
 * envelope shape every other language's generated client also produces,
 * verified against the same conventions the TypeScript SDK's vendored
 * {@code vendor/csilgen-transport/rpc.ts} implements.
 *
 * <p>Only the byte-stream (TCP/TLS) carrier framing is needed here: a 4-byte
 * big-endian length prefix followed by the CBOR envelope (see
 * {@link StreamFraming}).
 */
public final class RpcEnvelope {
    private RpcEnvelope() {}

    public static final int VERSION = 1;
    public static final int TAG_ENCODED_CBOR = 24;

    /** Transport status registry (subset this SDK observes). {@code 0} = a typed reply is present. */
    public static final class Status {
        private Status() {}

        public static final int OK = 0;
        public static final int MALFORMED_ENVELOPE = 1;
        public static final int UNKNOWN_SERVICE_OR_OP = 2;
        public static final int UNAUTHENTICATED = 3;
        public static final int FORBIDDEN = 4;
        public static final int VERSION_UNSUPPORTED = 5;
        public static final int INTERNAL = 6;
        public static final int UNAVAILABLE = 7;
        public static final int DEADLINE_EXCEEDED = 8;
    }

    private static Value tag24(byte[] payload) {
        return Cbor.vtag(TAG_ENCODED_CBOR, Cbor.vbytes(payload));
    }

    private static byte[] untag24(Value v) {
        if (v instanceof Cbor.VTag t && t.tag() == TAG_ENCODED_CBOR && t.value() instanceof Cbor.VBytes b) {
            return b.value();
        }
        throw new SdkException(SdkException.Kind.PROTOCOL, "expected a tag-24 (encoded-cbor) payload");
    }

    private static void checkVersion(long v) {
        if (v != VERSION) {
            throw new SdkException(SdkException.Kind.PROTOCOL, "unsupported transport version " + v);
        }
    }

    /** A CSIL-RPC request (client &rarr; server). */
    public record Request(String service, String op, Integer id, byte[] payload, String auth) {
        public Request(String service, String op, byte[] payload) {
            this(service, op, null, payload, null);
        }

        public byte[] encode() {
            List<Entry> entries = new ArrayList<>();
            Cbor.putText(entries, "service", service);
            Cbor.putText(entries, "op", op);
            entries.add(Cbor.entry("v", Cbor.vint(VERSION)));
            entries.add(Cbor.entry("payload", tag24(payload)));
            if (id != null) {
                entries.add(Cbor.entry("id", Cbor.vint(id)));
            }
            Cbor.putOptText(entries, "auth", auth);
            return Cbor.encode(Cbor.vmap(entries));
        }
    }

    public static Request decodeRequest(byte[] bytes) {
        Value v = Cbor.decode(bytes);
        checkVersion(Cbor.asInt(Cbor.require(v, "v")));
        byte[] payload = untag24(Cbor.require(v, "payload"));
        String service = Cbor.requireText(v, "service");
        String op = Cbor.requireText(v, "op");
        Value idField = Cbor.mapGet(v, "id");
        Integer id = idField == null ? null : (int) Cbor.asInt(idField);
        String auth = Cbor.optText(v, "auth");
        return new Request(service, op, id, payload, auth);
    }

    /** A CSIL-RPC response (server &rarr; client). */
    public record Response(Integer id, int status, String variant, String error, byte[] payload) {
        public static Response ok(String variant, byte[] payload) {
            return new Response(null, Status.OK, variant, null, payload);
        }

        public static Response transportError(int status, String message) {
            return new Response(null, status, null, message, new byte[0]);
        }

        public boolean isOk() {
            return status == Status.OK;
        }

        public byte[] encode() {
            List<Entry> entries = new ArrayList<>();
            entries.add(Cbor.entry("v", Cbor.vint(VERSION)));
            entries.add(Cbor.entry("status", Cbor.vint(status)));
            entries.add(Cbor.entry("payload", tag24(payload)));
            if (id != null) {
                entries.add(Cbor.entry("id", Cbor.vint(id)));
            }
            Cbor.putOptText(entries, "variant", variant);
            Cbor.putOptText(entries, "error", error);
            return Cbor.encode(Cbor.vmap(entries));
        }
    }

    public static Response decodeResponse(byte[] bytes) {
        Value v = Cbor.decode(bytes);
        checkVersion(Cbor.asInt(Cbor.require(v, "v")));
        Value payloadField = Cbor.mapGet(v, "payload");
        byte[] payload = payloadField == null ? new byte[0] : untag24(payloadField);
        int status = (int) Cbor.asInt(Cbor.require(v, "status"));
        Value idField = Cbor.mapGet(v, "id");
        Integer id = idField == null ? null : (int) Cbor.asInt(idField);
        String variant = Cbor.optText(v, "variant");
        String error = Cbor.optText(v, "error");
        return new Response(id, status, variant, error, payload);
    }
}
