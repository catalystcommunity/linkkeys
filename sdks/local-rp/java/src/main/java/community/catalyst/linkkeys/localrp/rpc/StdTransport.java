package community.catalyst.linkkeys.localrp.rpc;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

import community.catalyst.linkkeys.localrp.SdkException;

/** Default {@link Transport}: a plain blocking {@link Socket} dialer, gated only by {@link #policy}. */
public final class StdTransport implements Transport {
    private final AddressPolicy policy;
    private final int connectTimeoutMillis;
    private final int ioTimeoutMillis;

    public StdTransport() {
        this(AddressPolicy.PERMISSIVE, 10_000, 30_000);
    }

    public StdTransport(AddressPolicy policy) {
        this(policy, 10_000, 30_000);
    }

    public StdTransport(AddressPolicy policy, int connectTimeoutMillis, int ioTimeoutMillis) {
        this.policy = policy;
        this.connectTimeoutMillis = connectTimeoutMillis;
        this.ioTimeoutMillis = ioTimeoutMillis;
    }

    @Override
    public Socket dial(String hostPort) {
        int idx = hostPort.lastIndexOf(':');
        if (idx < 0) {
            throw new SdkException(SdkException.Kind.TRANSPORT, hostPort + ": missing port");
        }
        String host = hostPort.substring(0, idx);
        int port;
        try {
            port = Integer.parseInt(hostPort.substring(idx + 1));
        } catch (NumberFormatException e) {
            throw new SdkException(SdkException.Kind.TRANSPORT, hostPort + ": invalid port", e);
        }

        InetAddress[] addrs;
        try {
            addrs = InetAddress.getAllByName(host);
        } catch (java.net.UnknownHostException e) {
            throw new SdkException(SdkException.Kind.TRANSPORT, hostPort + ": resolve failed: " + e.getMessage(), e);
        }

        SdkException lastError = null;
        for (InetAddress addr : addrs) {
            if (policy == AddressPolicy.PUBLIC_ONLY && isNonPublic(addr)) {
                lastError = new SdkException(
                        SdkException.Kind.TRANSPORT,
                        addr.getHostAddress() + ": refusing non-public address under AddressPolicy.PUBLIC_ONLY");
                continue;
            }
            try {
                Socket socket = new Socket();
                socket.connect(new InetSocketAddress(addr, port), connectTimeoutMillis);
                socket.setSoTimeout(ioTimeoutMillis);
                return socket;
            } catch (IOException e) {
                lastError = new SdkException(SdkException.Kind.TRANSPORT, hostPort + ": " + e.getMessage(), e);
            }
        }
        if (lastError != null) {
            throw lastError;
        }
        throw new SdkException(SdkException.Kind.TRANSPORT, hostPort + ": no address resolved");
    }

    /**
     * True for loopback/private/link-local/CGNAT/documentation/unspecified
     * addresses. Only consulted under {@link AddressPolicy#PUBLIC_ONLY},
     * never by default.
     */
    static boolean isNonPublic(InetAddress addr) {
        if (addr.isLoopbackAddress()
                || addr.isSiteLocalAddress()
                || addr.isLinkLocalAddress()
                || addr.isAnyLocalAddress()
                || addr.isMulticastAddress()) {
            return true;
        }
        byte[] a = addr.getAddress();
        if (a.length == 4) {
            int o0 = a[0] & 0xff;
            int o1 = a[1] & 0xff;
            // CGNAT 100.64.0.0/10
            if (o0 == 100 && (o1 & 0xc0) == 0x40) {
                return true;
            }
            // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (documentation)
            if (o0 == 192 && o1 == 0 && (a[2] & 0xff) == 2) {
                return true;
            }
            if (o0 == 198 && o1 == 51 && (a[2] & 0xff) == 100) {
                return true;
            }
            if (o0 == 203 && o1 == 0 && (a[2] & 0xff) == 113) {
                return true;
            }
            // 255.255.255.255 broadcast
            if (o0 == 255 && o1 == 255 && (a[2] & 0xff) == 255 && (a[3] & 0xff) == 255) {
                return true;
            }
        } else if (a.length == 16) {
            // ULA fc00::/7
            if ((a[0] & 0xfe) == 0xfc) {
                return true;
            }
        }
        return false;
    }
}
