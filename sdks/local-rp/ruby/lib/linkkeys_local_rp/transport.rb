# frozen_string_literal: true

require 'socket'
require 'ipaddr'

module LinkkeysLocalRp
  # The TCP dial seam.
  #
  # Mirrors `sdks/local-rp/rust/src/transport.rs`. Deliberately narrow: this
  # seam only *connects a byte stream* to `host:port`. TLS (certificate-pin
  # verification against DNS `fp=` records) is layered on top in `tls.rb`,
  # not here, so a test double can swap out "how do I open a socket"
  # without also faking a TLS handshake.
  #
  # Per the design doc's Wire Precision ("SDK endpoint discovery and
  # pinning"): the Rust `linkkeys-rpc-client`'s non-public-address refusal
  # is a SERVER-SIDE SSRF guard and must NOT be inherited as this SDK's
  # default -- "connecting from a LAN box to wherever `_linkkeys_apis`
  # points is the entire point of this mode." The default policy here is
  # `AddressPolicy::PERMISSIVE`. `AddressPolicy::PUBLIC_ONLY` is an opt-in
  # for integrators who specifically want that stricter posture; nothing in
  # this package selects it automatically.
  module Transport
    class Error < StandardError; end
    class ConnectFailed < Error; end
    class AddressDenied < Error; end

    module AddressPolicy
      PERMISSIVE = :permissive
      PUBLIC_ONLY = :public_only
    end

    # True for loopback/private/link-local/CGNAT/documentation/unspecified
    # addresses. Only consulted under AddressPolicy::PUBLIC_ONLY, never by
    # default.
    def self.non_public?(ip_str)
      ip = IPAddr.new(ip_str)
      if ip.ipv4?
        octets = ip.hton.bytes
        cgnat = octets[0] == 100 && (octets[1] & 0xC0) == 0x40
        loopback = ip.to_range.include?(IPAddr.new('127.0.0.1'))
        private_range = %w[10.0.0.0/8 172.16.0.0/12 192.168.0.0/16].any? { |c| IPAddr.new(c).include?(ip) }
        link_local = IPAddr.new('169.254.0.0/16').include?(ip)
        unspecified = ip_str == '0.0.0.0'
        broadcast = ip_str == '255.255.255.255'
        documentation = %w[192.0.2.0/24 198.51.100.0/24 203.0.113.0/24].any? { |c| IPAddr.new(c).include?(ip) }
        loopback || private_range || link_local || unspecified || broadcast || documentation || cgnat
      else
        return non_public?(ip.native.to_s) if ip.ipv4_mapped?

        loopback = ip == IPAddr.new('::1')
        unspecified = ip == IPAddr.new('::')
        multicast = IPAddr.new('ff00::/8').include?(ip)
        link_local = IPAddr.new('fe80::/10').include?(ip)
        ula = IPAddr.new('fc00::/7').include?(ip)
        loopback || unspecified || multicast || link_local || ula
      end
    end

    # Default Transport: a plain blocking TCP socket, gated only by
    # `policy` (permissive unless the caller opts into
    # AddressPolicy::PUBLIC_ONLY).
    class StdTransport
      attr_reader :policy, :connect_timeout, :io_timeout

      def initialize(policy: AddressPolicy::PERMISSIVE, connect_timeout: 10, io_timeout: 30)
        @policy = policy
        @connect_timeout = connect_timeout
        @io_timeout = io_timeout
      end

      def dial(host_port)
        idx = host_port.rindex(':')
        raise ConnectFailed, "#{host_port}: missing host" if idx.nil? || idx.zero?

        host = host_port[0...idx]
        port_str = host_port[(idx + 1)..]
        port = Integer(port_str, exception: false)
        raise ConnectFailed, "#{host_port}: invalid port" if port.nil?

        addrinfos = begin
          Socket.getaddrinfo(host, port, nil, Socket::SOCK_STREAM)
        rescue SocketError => e
          raise ConnectFailed, "#{host_port}: resolve failed: #{e.message}"
        end

        last_err = nil
        addrinfos.each do |_family, _port, _canon, ip_str, af, _socktype, _protocol|
          if @policy == AddressPolicy::PUBLIC_ONLY && Transport.non_public?(ip_str)
            last_err = AddressDenied.new("#{ip_str}: refusing non-public address under AddressPolicy::PUBLIC_ONLY")
            next
          end
          begin
            sock = Socket.new(af, Socket::SOCK_STREAM, 0)
            sockaddr = Socket.pack_sockaddr_in(port, ip_str)
            connect_with_timeout(sock, sockaddr, @connect_timeout)
            sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, [@io_timeout, 0].pack('l_2'))
            sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDTIMEO, [@io_timeout, 0].pack('l_2'))
            return sock
          rescue StandardError => e
            last_err = ConnectFailed.new("#{host_port}: #{e.message}")
            next
          end
        end

        raise(last_err || ConnectFailed.new("#{host_port}: no address resolved"))
      end

      private

      def connect_with_timeout(sock, sockaddr, timeout)
        sock.connect_nonblock(sockaddr)
      rescue IO::WaitWritable
        if IO.select(nil, [sock], nil, timeout)
          begin
            sock.connect_nonblock(sockaddr)
          rescue Errno::EISCONN
            nil
          end
        else
          sock.close
          raise ConnectFailed, 'connect timed out'
        end
      end
    end
  end
end
