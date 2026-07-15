defmodule LinkkeysLocalRp.Dns do
  @moduledoc """
  DNS TXT lookup seam + `_linkkeys`/`_linkkeys_apis` record parsing and key
  pinning.

  Mirrors `crates/liblinkkeys/src/dns.rs` (record parsing, pinning, vouch
  verification, `trust_keys`) plus the DNS *lookup* seam itself
  (`sdks/local-rp/rust/src/dns.rs`'s `DnsResolver` trait). Per the design
  doc's "Required Network Access" / "SDK endpoint discovery and pinning":
  the resolver is configurable, defaulting to the system resolver (OTP's
  `:inet_res`) — LAN resolver spoofing is an accepted, documented tradeoff
  for this mode.
  """

  alias LinkkeysLocalRp.Crypto
  alias LinkkeysLocalRp.Timeutil

  @default_tcp_port 4987
  def default_tcp_port, do: @default_tcp_port

  defmodule DnsParseError do
    defexception [:message, :reason]

    @impl true
    def exception(reason) when is_atom(reason) do
      %__MODULE__{message: "DNS record parse error: #{reason}", reason: reason}
    end

    def exception(message) when is_binary(message) do
      %__MODULE__{message: message, reason: :invalid_format}
    end
  end

  defmodule LinkKeysRecord do
    defstruct fingerprints: []
  end

  defmodule LinkKeysApis do
    defstruct tcp: nil, https_base: nil
  end

  def linkkeys_dns_name(domain), do: "_linkkeys.#{domain}"
  def linkkeys_apis_dns_name(domain), do: "_linkkeys_apis.#{domain}"

  defp require_lk1_version!(parts) do
    version =
      Enum.find_value(parts, fn p ->
        if String.starts_with?(p, "v="), do: String.slice(p, 2..-1//1)
      end)

    case version do
      nil -> raise DnsParseError, :missing_version
      "lk1" -> :ok
      _ -> raise DnsParseError, :unsupported_version
    end
  end

  @doc "Parse a `_linkkeys.{domain}` TXT record: `v=lk1 fp={hex} fp={hex} ...`."
  def parse_linkkeys_txt(txt) do
    parts = String.split(txt)
    require_lk1_version!(parts)

    fingerprints =
      parts
      |> Enum.filter(&String.starts_with?(&1, "fp="))
      |> Enum.map(&String.slice(&1, 3..-1//1))

    %LinkKeysRecord{fingerprints: fingerprints}
  end

  defp normalize_tcp_endpoint(""), do: ""

  defp normalize_tcp_endpoint(value) do
    if String.contains?(value, ":"), do: value, else: "#{value}:#{@default_tcp_port}"
  end

  @doc "Parse a `_linkkeys_apis.{domain}` TXT record: `v=lk1 tcp={host[:port]} https={host[:port][/path]}`."
  def parse_linkkeys_apis_txt(txt) do
    parts = String.split(txt)
    require_lk1_version!(parts)

    tcp_raw =
      Enum.find_value(parts, fn p -> if String.starts_with?(p, "tcp="), do: String.slice(p, 4..-1//1) end)

    tcp = if tcp_raw && tcp_raw != "", do: normalize_tcp_endpoint(tcp_raw)

    https_raw =
      Enum.find_value(parts, fn p -> if String.starts_with?(p, "https="), do: String.slice(p, 6..-1//1) end)

    https_base = if https_raw && https_raw != "", do: "https://#{https_raw}"

    if is_nil(tcp) and is_nil(https_base) do
      raise DnsParseError, :missing_apis_endpoint
    end

    %LinkKeysApis{tcp: tcp, https_base: https_base}
  end

  @doc "A fingerprint is exactly 64 lowercase-or-uppercase hex characters (a SHA-256 digest)."
  def valid_fingerprint?(fp) when is_binary(fp) do
    byte_size(fp) == 64 and String.match?(fp, ~r/^[0-9a-fA-F]{64}$/)
  end

  def valid_fingerprint?(_), do: false

  @doc "Recompute each candidate key's fingerprint (never trust the wire `fingerprint` field) and keep only keys whose recomputed fingerprint is a member of `pinned`."
  def pin_keys_to_fingerprints(keys, pinned) do
    pinned_lower = pinned |> Enum.filter(&valid_fingerprint?/1) |> Enum.map(&String.downcase/1) |> MapSet.new()
    Enum.filter(keys, fn k -> MapSet.member?(pinned_lower, String.downcase(Crypto.fingerprint(k.public_key))) end)
  end

  @key_vouch_tag "linkkeys-key-vouch-v1"

  def key_vouch_payload(enc_fingerprint, enc_expires_at) do
    LinkkeysLocalRp.Cbor.encode([@key_vouch_tag, enc_fingerprint, enc_expires_at])
  end

  @doc "Verify that `signing_key` vouches for `enc_key` (encryption keys are not published in DNS; they are trusted only via a DNS-pinned signing key's vouch)."
  def verify_key_vouch?(enc_key, signing_key, now) do
    cond do
      enc_key.signed_by_key_id != signing_key.key_id ->
        false

      not signing_key_currently_valid?(signing_key, now) ->
        false

      is_nil(enc_key.key_signature) ->
        false

      true ->
        recomputed_fp = Crypto.fingerprint(enc_key.public_key)
        payload = key_vouch_payload(recomputed_fp, enc_key.expires_at)
        Crypto.ed25519_verify(payload, enc_key.key_signature, signing_key.public_key)
    end
  end

  defp signing_key_currently_valid?(key, now) do
    if key.revoked_at != nil do
      false
    else
      case safe_parse(key.expires_at) do
        {:ok, expires} -> DateTime.compare(now, expires) != :gt
        {:error, _} -> false
      end
    end
  end

  defp safe_parse(s) do
    {:ok, Timeutil.parse_rfc3339(s)}
  rescue
    _ -> {:error, :bad_timestamp}
  end

  @doc "Establish the trusted key set from a fetched key list and the DNS-pinned fingerprint set. Signing keys are pinned directly; encryption keys are trusted only when a pinned signing key vouches for them. Callers MUST treat an empty result as 'no trustworthy keys' and fail closed."
  def trust_keys(keys, pinned, now) do
    signing = Enum.filter(keys, fn k -> k.key_usage == "sign" end)
    pinned_signing = pin_keys_to_fingerprints(signing, pinned)

    encryption_trusted =
      keys
      |> Enum.filter(fn k -> k.key_usage == "encrypt" end)
      |> Enum.filter(fn k -> Enum.any?(pinned_signing, fn sk -> verify_key_vouch?(k, sk, now) end) end)

    pinned_signing ++ encryption_trusted
  end

  @typedoc "Caller-injected DNS TXT lookup seam — a plain 1-arity function, the idiomatic Elixir shape for a swappable capability (mirrors `LinkkeysLocalRp.Transport.t/0`). Each returned string is one TXT record's content (the concatenation of its character-strings)."
  @type resolver :: (name :: String.t() -> {:ok, [String.t()]} | {:error, term})

  @doc """
  Default DNS resolver: the OS-configured resolver via OTP's
  `:inet_res`. Per the design doc's "Decided" section, resolver spoofing
  on a LAN is an accepted, documented tradeoff for this mode; operators
  wanting hardening can inject their own resolver function (e.g. a DoH
  client) instead — anywhere this SDK accepts a `resolver`, any function
  of the same 1-arity shape works.
  """
  @spec system_resolver(name :: String.t()) :: {:ok, [String.t()]} | {:error, term}
  def system_resolver(name) do
    case :inet_res.lookup(String.to_charlist(name), :in, :txt) do
      [] ->
        {:error, {:dns_lookup_failed, name}}

      results when is_list(results) ->
        {:ok,
         Enum.map(results, fn char_lists ->
           char_lists
           |> Enum.map(&IO.iodata_to_binary/1)
           |> IO.iodata_to_binary()
         end)}
    end
  rescue
    e -> {:error, {:dns_lookup_failed, name, e}}
  end
end
