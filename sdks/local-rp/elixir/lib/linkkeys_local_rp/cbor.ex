defmodule LinkkeysLocalRp.Cbor do
  @moduledoc """
  Hand-written canonical CBOR codec (RFC 8949).

  There is no csilgen Elixir target (a request for one has been filed —
  see the repo root's `dns-less-local-rp-design.md` instructions and
  `~/repos/catalystcommunity/csilgen/docs/csilgen-requests/`), so this SDK
  hand-rolls the minimal wire codec every other SDK gets generated. This
  module is deliberately narrow: it only supports the value shapes the
  LinkKeys local-RP protocol actually uses (integers, floats, booleans,
  nil, byte strings, UTF-8 text strings, arrays, maps with text-string
  keys, and tag 24 "encoded CBOR data item" for the CSIL-RPC envelope).

  **Canonical encoding is mandatory** (Wire Precision: signatures are
  computed over exact shipped bytes, and several conformance vectors are
  byte-identical fixtures produced by the Rust reference implementation):

  - Definite-length encoding only (no indefinite-length/streaming forms).
  - Map keys are sorted by the bytewise lexicographic order of their own
    *encoded* CBOR bytes (RFC 8949 §4.2.1) — NOT by Elixir/Erlang term
    ordering and NOT by insertion order. `encode_map/1` below implements
    this explicitly with `compare_bytes/2` rather than relying on any
    language-level binary ordering assumption.

  Byte strings and UTF-8 text strings are both represented as Elixir
  binaries at the language level, so this module needs an explicit wrapper
  to disambiguate which CBOR major type a given binary should become on
  encode: plain Elixir binaries/strings always encode as CBOR major type 3
  (text); anything that must become CBOR major type 2 (byte string) must be
  wrapped in `%LinkkeysLocalRp.Cbor.Bytes{}` via `bytes/1`. On decode, the
  mirror image holds: CBOR text strings decode to plain Elixir binaries,
  CBOR byte strings decode to `%Bytes{}` — callers that always know which
  field is bytes vs. text (every hand-written `to_cbor`/`from_cbor` in
  `LinkkeysLocalRp.Types`) unwrap immediately via `bytes!/1`.
  """

  defmodule Bytes do
    @moduledoc "Wrapper marking a binary as a CBOR byte string (major type 2), not text."
    defstruct value: <<>>
  end

  defmodule Tag do
    @moduledoc "A CBOR tagged value (major type 6): a tag number wrapping a value tree."
    defstruct tag: 0, value: nil
  end

  @type value ::
          nil
          | boolean
          | integer
          | float
          | binary
          | %Bytes{}
          | %Tag{}
          | [value]
          | %{optional(binary) => value}

  @doc "Wrap a raw binary so it encodes as a CBOR byte string."
  @spec bytes(binary) :: %Bytes{}
  def bytes(bin) when is_binary(bin), do: %Bytes{value: bin}

  @doc "Unwrap a decoded `%Bytes{}` back to a raw binary. Raises on any other shape — a byte-string field decoded to something else (in particular, a CBOR text string, which also decodes to a plain Elixir binary) is a wire-format bug, not something to paper over. A permissive fallback here would silently accept a CBOR major-type-3 (text) value anywhere a major-type-2 (bytes) value is required, defeating the whole point of the `%Bytes{}` wrapper — see `claims.json`'s `claim_value_as_cbor_text_rejected` conformance vector."
  @spec bytes!(value) :: binary
  def bytes!(%Bytes{value: v}), do: v

  def bytes!(other) do
    raise ArgumentError, "csil cbor: expected a CBOR byte string (bstr), got #{inspect(other)}"
  end

  @doc "Unwrap a decoded value expected to be CBOR text (a plain Elixir binary)."
  @spec text!(value) :: binary
  def text!(v) when is_binary(v), do: v

  @doc "Encode a value tree to canonical CBOR bytes."
  @spec encode(value) :: binary
  def encode(value), do: IO.iodata_to_binary(enc(value))

  @doc "Decode canonical CBOR bytes into a value tree. Raises if the input has trailing bytes after one complete value (mirrors the generated codecs' own `cbor_decode` in sibling SDKs)."
  @spec decode(binary) :: value
  def decode(data) when is_binary(data) do
    {value, rest} = dec(data)

    if rest != <<>> do
      raise ArgumentError, "csil cbor: trailing bytes after decoding one value"
    end

    value
  end

  # --- encode ---------------------------------------------------------

  defp enc(nil), do: <<0xF6>>
  defp enc(true), do: <<0xF5>>
  defp enc(false), do: <<0xF4>>
  defp enc(i) when is_integer(i) and i >= 0, do: head(0, i)
  defp enc(i) when is_integer(i), do: head(1, -1 - i)

  defp enc(f) when is_float(f) do
    <<0xFB, f::float-64-big>>
  end

  defp enc(%Bytes{value: b}), do: [head(2, byte_size(b)), b]

  defp enc(s) when is_binary(s), do: [head(3, byte_size(s)), s]

  defp enc(%Tag{tag: t, value: v}), do: [head(6, t), enc(v)]

  defp enc(list) when is_list(list) do
    [head(4, length(list)) | Enum.map(list, &enc/1)]
  end

  defp enc(map) when is_map(map), do: encode_map(map)

  defp enc(other) do
    raise ArgumentError, "csil cbor: cannot encode value #{inspect(other)}"
  end

  @doc false
  def encode_map(map) do
    entries =
      Enum.map(map, fn {k, v} ->
        key_bytes = IO.iodata_to_binary(enc(k))
        {key_bytes, v}
      end)

    sorted =
      Enum.sort(entries, fn {ka, _}, {kb, _} -> compare_bytes(ka, kb) != :gt end)

    [
      head(5, length(sorted))
      | Enum.map(sorted, fn {kbin, v} -> [kbin, enc(v)] end)
    ]
  end

  # Bytewise lexicographic comparison of two binaries, independent of any
  # Erlang/Elixir term-ordering assumption about binaries — this is exactly
  # what RFC 8949 §4.2.1 canonical map-key ordering requires.
  @doc false
  def compare_bytes(<<>>, <<>>), do: :eq
  def compare_bytes(<<>>, _), do: :lt
  def compare_bytes(_, <<>>), do: :gt

  def compare_bytes(<<x, resta::binary>>, <<y, restb::binary>>) do
    cond do
      x < y -> :lt
      x > y -> :gt
      true -> compare_bytes(resta, restb)
    end
  end

  defp head(major, n) do
    mt = Bitwise.bsl(major, 5)

    cond do
      n < 24 ->
        <<Bitwise.bor(mt, n)>>

      n < 0x100 ->
        <<Bitwise.bor(mt, 24), n::8>>

      n < 0x10000 ->
        <<Bitwise.bor(mt, 25), n::16>>

      n < 0x100000000 ->
        <<Bitwise.bor(mt, 26), n::32>>

      true ->
        <<Bitwise.bor(mt, 27), n::64>>
    end
  end

  # --- decode ----------------------------------------------------------

  defp dec(<<ib, rest::binary>>) do
    major = Bitwise.bsr(ib, 5)
    low = Bitwise.band(ib, 0x1F)

    case major do
      7 ->
        dec_simple(low, rest)

      0 ->
        {arg, rest2} = read_arg(low, rest)
        {arg, rest2}

      1 ->
        {arg, rest2} = read_arg(low, rest)
        {-1 - arg, rest2}

      2 ->
        dec_bytes(low, rest)

      3 ->
        dec_text(low, rest)

      4 ->
        dec_array(low, rest)

      5 ->
        dec_map(low, rest)

      6 ->
        dec_tag(low, rest)

      _ ->
        raise ArgumentError, "csil cbor: bad major type #{major}"
    end
  end

  defp dec_simple(20, rest), do: {false, rest}
  defp dec_simple(21, rest), do: {true, rest}
  defp dec_simple(22, rest), do: {nil, rest}
  defp dec_simple(23, rest), do: {nil, rest}

  defp dec_simple(26, <<f::float-32-big, rest::binary>>), do: {f, rest}
  defp dec_simple(27, <<f::float-64-big, rest::binary>>), do: {f, rest}
  defp dec_simple(low, _rest), do: raise(ArgumentError, "csil cbor: unsupported simple value #{low}")

  defp read_arg(low, rest) when low < 24, do: {low, rest}
  defp read_arg(24, <<n::8, rest::binary>>), do: {n, rest}
  defp read_arg(25, <<n::16, rest::binary>>), do: {n, rest}
  defp read_arg(26, <<n::32, rest::binary>>), do: {n, rest}
  defp read_arg(27, <<n::64, rest::binary>>), do: {n, rest}
  defp read_arg(low, _rest), do: raise(ArgumentError, "csil cbor: bad length encoding #{low}")

  defp dec_bytes(low, rest) do
    {n, rest2} = read_arg(low, rest)
    <<b::binary-size(^n), rest3::binary>> = rest2
    {%Bytes{value: b}, rest3}
  end

  defp dec_text(low, rest) do
    {n, rest2} = read_arg(low, rest)
    <<b::binary-size(^n), rest3::binary>> = rest2
    {b, rest3}
  end

  defp dec_array(low, rest) do
    {n, rest2} = read_arg(low, rest)
    dec_array_items(n, rest2, [])
  end

  defp dec_array_items(0, rest, acc), do: {Enum.reverse(acc), rest}

  defp dec_array_items(n, rest, acc) do
    {item, rest2} = dec(rest)
    dec_array_items(n - 1, rest2, [item | acc])
  end

  defp dec_map(low, rest) do
    {n, rest2} = read_arg(low, rest)
    dec_map_items(n, rest2, %{})
  end

  defp dec_map_items(0, rest, acc), do: {acc, rest}

  defp dec_map_items(n, rest, acc) do
    {k, rest2} = dec(rest)
    {v, rest3} = dec(rest2)
    dec_map_items(n - 1, rest3, Map.put(acc, k, v))
  end

  defp dec_tag(low, rest) do
    {t, rest2} = read_arg(low, rest)
    {inner, rest3} = dec(rest2)
    {%Tag{tag: t, value: inner}, rest3}
  end
end
