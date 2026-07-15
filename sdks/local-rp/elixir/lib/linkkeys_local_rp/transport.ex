defmodule LinkkeysLocalRp.Transport do
  @moduledoc """
  The TCP dial seam.

  Injectable as a plain 1-arity function — the idiomatic Elixir shape for
  a swappable capability — rather than a behaviour/struct pair: `t:transport/0`
  is `(host_port :: String.t() -> {:ok, socket} | {:error, term})`. Tests
  inject a fake by passing any function of that shape; `LinkkeysLocalRp.Rpc`
  defaults to `&dial/1` (`policy: :permissive`) when the caller supplies
  none.

  Deliberately narrow: this seam only *connects a byte stream* to
  `host:port`, returning a passive, binary `:gen_tcp` socket. TLS
  (certificate-pin verification against DNS `fp=` records) is layered on
  top in `LinkkeysLocalRp.Tls`, not here, so a test double can swap out
  "how do I open a socket" without also faking a TLS handshake.

  Per the design doc's Wire Precision ("SDK endpoint discovery and
  pinning"): the Rust `linkkeys-rpc-client` refuses non-public peer
  addresses as a *server-side* SSRF guard. SDKs must not inherit that
  refusal as a default — "connecting from a LAN box to wherever
  `_linkkeys_apis` points is the entire point of this mode." The default
  policy here is `:permissive`. `:public_only` is an opt-in for
  integrators who specifically want that stricter posture; nothing in
  this package selects it automatically.
  """

  @type socket :: :gen_tcp.socket()
  @type t :: (String.t() -> {:ok, socket} | {:error, term})

  defmodule ConnectFailed do
    defexception [:message]
  end

  defmodule AddressDenied do
    defexception [:message]
  end

  @doc """
  Default transport implementation: dial `host_port` as a plain, passive,
  binary TCP socket. `opts`:

  - `:policy` — `:permissive` (default) or `:public_only` (refuse
    loopback/private/link-local/CGNAT/reserved destination addresses —
    an opt-in SSRF-guard posture, never applied automatically).
  - `:connect_timeout` — milliseconds, default `10_000`.
  - `:io_timeout` — milliseconds, default `30_000` (applied as the
    socket's send timeout after connect).
  """
  @spec dial(String.t(), keyword) :: {:ok, socket} | {:error, term}
  def dial(host_port, opts \\ []) do
    policy = Keyword.get(opts, :policy, :permissive)
    connect_timeout = Keyword.get(opts, :connect_timeout, 10_000)
    io_timeout = Keyword.get(opts, :io_timeout, 30_000)

    with {:ok, host, port} <- parse_host_port(host_port) do
      dial_resolved(host_port, host, port, policy, connect_timeout, io_timeout)
    end
  end

  defp parse_host_port(host_port) do
    case String.split(host_port, ":") do
      [host, port_str] ->
        case Integer.parse(port_str) do
          {port, ""} -> {:ok, host, port}
          _ -> {:error, %ConnectFailed{message: "#{host_port}: invalid port"}}
        end

      _ ->
        {:error, %ConnectFailed{message: "#{host_port}: expected host:port"}}
    end
  end

  defp dial_resolved(host_port, host, port, policy, connect_timeout, io_timeout) do
    charlist_host = String.to_charlist(host)

    addrs =
      case :inet.getaddrs(charlist_host, :inet) do
        {:ok, v4} -> v4
        {:error, _} -> []
      end ++
        case :inet.getaddrs(charlist_host, :inet6) do
          {:ok, v6} -> v6
          {:error, _} -> []
        end

    try_addrs(host_port, addrs, port, policy, connect_timeout, io_timeout, nil)
  end

  defp try_addrs(host_port, [], _port, _policy, _ct, _iot, nil),
    do: {:error, %ConnectFailed{message: "#{host_port}: no address resolved"}}

  defp try_addrs(_host_port, [], _port, _policy, _ct, _iot, last_err), do: {:error, last_err}

  defp try_addrs(host_port, [addr | rest], port, policy, connect_timeout, io_timeout, _last_err) do
    if policy == :public_only and non_public_address?(addr) do
      err = %AddressDenied{message: "#{:inet.ntoa(addr)}: refusing non-public address under policy: public_only"}
      try_addrs(host_port, rest, port, policy, connect_timeout, io_timeout, err)
    else
      case :gen_tcp.connect(addr, port, [:binary, active: false, packet: :raw], connect_timeout) do
        {:ok, sock} ->
          :inet.setopts(sock, send_timeout: io_timeout)
          {:ok, sock}

        {:error, reason} ->
          err = %ConnectFailed{message: "#{host_port}: #{inspect(reason)}"}
          try_addrs(host_port, rest, port, policy, connect_timeout, io_timeout, err)
      end
    end
  end

  # Loopback / private (RFC1918) / link-local / CGNAT / reserved — only
  # consulted under policy: :public_only, never by default.
  defp non_public_address?({127, _, _, _}), do: true
  defp non_public_address?({10, _, _, _}), do: true
  defp non_public_address?({172, b, _, _}) when b >= 16 and b <= 31, do: true
  defp non_public_address?({192, 168, _, _}), do: true
  defp non_public_address?({169, 254, _, _}), do: true
  defp non_public_address?({100, b, _, _}) when b >= 64 and b <= 127, do: true
  defp non_public_address?({0, 0, 0, 0}), do: true
  defp non_public_address?({255, 255, 255, 255}), do: true

  defp non_public_address?({0, 0, 0, 0, 0, 0, 0, 1}), do: true
  defp non_public_address?({0, 0, 0, 0, 0, 0, 0, 0}), do: true
  defp non_public_address?({a, _, _, _, _, _, _, _}) when a >= 0xFE80 and a <= 0xFEBF, do: true
  defp non_public_address?({a, _, _, _, _, _, _, _}) when a >= 0xFC00 and a <= 0xFDFF, do: true

  defp non_public_address?(_), do: false
end
