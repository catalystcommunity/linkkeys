namespace LinkKeys.LocalRp.Rpc;

/// <summary>
/// CSIL-RPC byte-stream (TCP/TLS) carrier framing: a 4-byte big-endian unsigned length
/// prefix, then that many bytes of CBOR envelope (<c>csil-rpc-transport.md</c> §2.3).
/// </summary>
internal static class StreamFraming
{
    /// <summary>Mirrors the Rust/Go/Java reference clients' own cap, so a forged length prefix cannot drive an unbounded allocation.</summary>
    internal const int MaxFrameSize = 1024 * 1024;

    public static void SendFrame(Stream stream, byte[] data)
    {
        try
        {
            int len = data.Length;
            stream.Write([(byte)(len >> 24), (byte)(len >> 16), (byte)(len >> 8), (byte)len]);
            stream.Write(data);
            stream.Flush();
        }
        catch (IOException e)
        {
            throw new SdkException(SdkException.ErrorKind.Transport, e.Message, e);
        }
    }

    public static byte[] ReadFrame(Stream stream)
    {
        try
        {
            var lenBuf = ReadExact(stream, 4);
            int len = (lenBuf[0] << 24) | (lenBuf[1] << 16) | (lenBuf[2] << 8) | lenBuf[3];
            if (len < 0 || len > MaxFrameSize)
            {
                throw new SdkException(SdkException.ErrorKind.Protocol, $"peer frame too large ({len} bytes, max {MaxFrameSize})");
            }

            return ReadExact(stream, len);
        }
        catch (IOException e)
        {
            throw new SdkException(SdkException.ErrorKind.Transport, e.Message, e);
        }
    }

    private static byte[] ReadExact(Stream stream, int n)
    {
        var buf = new byte[n];
        int off = 0;
        while (off < n)
        {
            int read = stream.Read(buf, off, n - off);
            if (read <= 0)
            {
                throw new SdkException(SdkException.ErrorKind.Transport, "connection closed before expected bytes arrived");
            }

            off += read;
        }

        return buf;
    }
}
