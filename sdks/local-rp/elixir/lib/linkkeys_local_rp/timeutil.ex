defmodule LinkkeysLocalRp.Timeutil do
  @moduledoc """
  Timestamp helpers shared by every module that checks freshness or puts a
  time on the wire. Every "current time" in this SDK is an explicit
  `DateTime.t()` parameter, never read internally from the system clock —
  mirroring `liblinkkeys`'s discipline so verification stays deterministic
  and testable against the fixed conformance vectors.

  Wire forms (see `docs/UPGRADING.md`, "Wire format: timestamps and enums"):

  - A CSIL `timestamp` field is CBOR tag 0 wrapping RFC 3339 text in UTC
    (`c0 74 "2026-01-01T00:00:00Z"`). `to_wire/1` / `from_wire!/1`.
  - Inside a signed TUPLE payload (claim, key revocation, key vouch) a time
    is a CBOR integer of whole Unix seconds. `signed_seconds/1` refuses a
    time with a fraction of a second: such a time cannot be signed, so a
    verifier fails closed instead of rounding.
  """

  alias LinkkeysLocalRp.Cbor

  @doc "Parse an RFC3339 timestamp into a UTC `DateTime.t()`. Raises `ArgumentError` on anything unparseable. `DateTime.from_iso8601/1` already normalizes any numeric UTC offset into an absolute UTC instant (`time_zone: \"Etc/UTC\"`), so no further zone conversion is needed."
  @spec parse_rfc3339(String.t()) :: DateTime.t()
  def parse_rfc3339(s) when is_binary(s) do
    case DateTime.from_iso8601(s) do
      {:ok, dt, _offset} -> dt
      {:error, reason} -> raise ArgumentError, "invalid RFC3339 timestamp #{inspect(s)}: #{inspect(reason)}"
    end
  end

  @doc "Render a `DateTime.t()` as RFC3339 UTC with a `Z` suffix, keeping any fraction of a second the value carries."
  @spec to_rfc3339(DateTime.t()) :: String.t()
  def to_rfc3339(%DateTime{} = dt) do
    dt |> DateTime.shift_zone!("Etc/UTC") |> DateTime.to_iso8601()
  end

  @doc "`dt` in UTC without its fraction of a second (rounded down). Use this for every time the SDK builds from `now`."
  @spec whole_seconds(DateTime.t()) :: DateTime.t()
  def whole_seconds(%DateTime{} = dt) do
    dt |> DateTime.shift_zone!("Etc/UTC") |> DateTime.truncate(:second)
  end

  @doc "Encode a `DateTime.t()` as a CSIL `timestamp`: CBOR tag 0 wrapping RFC 3339 UTC text."
  @spec to_wire(DateTime.t()) :: %Cbor.Tag{}
  def to_wire(%DateTime{} = dt), do: %Cbor.Tag{tag: 0, value: to_rfc3339(dt)}

  @doc "Encode an optional `DateTime.t()` (`nil` stays `nil`)."
  def to_wire_opt(nil), do: nil
  def to_wire_opt(%DateTime{} = dt), do: to_wire(dt)

  @doc "Decode a CSIL `timestamp` (CBOR tag 0 wrapping RFC 3339 text) into a UTC `DateTime.t()`. Raises `ArgumentError` on any other shape, including untagged text."
  @spec from_wire!(Cbor.value()) :: DateTime.t()
  def from_wire!(%Cbor.Tag{tag: 0, value: s}) when is_binary(s), do: parse_rfc3339(s)

  def from_wire!(other) do
    raise ArgumentError, "csil cbor: expected a timestamp (CBOR tag 0 + RFC 3339 text), got #{inspect(other)}"
  end

  @doc "Decode an optional CSIL `timestamp` (`nil` stays `nil`)."
  def from_wire_opt!(nil), do: nil
  def from_wire_opt!(v), do: from_wire!(v)

  @doc "Whole Unix seconds for a signed tuple payload. Returns `:error` when `dt` has a fraction of a second (such a time cannot be signed)."
  @spec signed_seconds(DateTime.t()) :: {:ok, integer} | :error
  def signed_seconds(%DateTime{microsecond: {us, _}} = dt) do
    if us == 0, do: {:ok, DateTime.to_unix(dt, :second)}, else: :error
  end
end
