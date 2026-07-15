package community.catalyst.linkkeys.localrp.rpc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import community.catalyst.linkkeys.localrp.SdkException;

/**
 * CSIL-RPC byte-stream (TCP/TLS) carrier framing: a 4-byte big-endian
 * unsigned length prefix, then that many bytes of CBOR envelope
 * (`csil-rpc-transport.md` &sect;2.3).
 */
final class StreamFraming {
    private StreamFraming() {}

    /** Mirrors the Rust/Go reference clients' own cap, so a forged length prefix cannot drive an unbounded allocation. */
    static final int MAX_FRAME_SIZE = 1024 * 1024;

    static void sendFrame(OutputStream out, byte[] data) {
        try {
            int len = data.length;
            out.write(new byte[] {
                (byte) (len >>> 24), (byte) (len >>> 16), (byte) (len >>> 8), (byte) len
            });
            out.write(data);
            out.flush();
        } catch (IOException e) {
            throw new SdkException(SdkException.Kind.TRANSPORT, e.getMessage(), e);
        }
    }

    static byte[] readFrame(InputStream in) {
        try {
            byte[] lenBuf = readExact(in, 4);
            int len = ((lenBuf[0] & 0xff) << 24)
                    | ((lenBuf[1] & 0xff) << 16)
                    | ((lenBuf[2] & 0xff) << 8)
                    | (lenBuf[3] & 0xff);
            if (len < 0 || len > MAX_FRAME_SIZE) {
                throw new SdkException(
                        SdkException.Kind.PROTOCOL, "peer frame too large (" + len + " bytes, max " + MAX_FRAME_SIZE + ")");
            }
            return readExact(in, len);
        } catch (IOException e) {
            throw new SdkException(SdkException.Kind.TRANSPORT, e.getMessage(), e);
        }
    }

    private static byte[] readExact(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n];
        int off = 0;
        while (off < n) {
            int read = in.read(buf, off, n - off);
            if (read < 0) {
                throw new SdkException(SdkException.Kind.TRANSPORT, "connection closed before expected bytes arrived");
            }
            off += read;
        }
        return buf;
    }
}
