defmodule LinkkeysLocalRp.Timeutil do
  @moduledoc """
  RFC3339 timestamp parse/format shared by every module that checks
  freshness. Every "current time" in this SDK is an explicit `DateTime.t()`
  parameter, never read internally from the system clock — mirroring
  `liblinkkeys`'s discipline so verification stays deterministic and
  testable against the fixed conformance vectors.
  """

  @doc "Parse an RFC3339 timestamp into a UTC `DateTime.t()`. Raises `ArgumentError` on anything unparseable. `DateTime.from_iso8601/1` already normalizes any numeric UTC offset into an absolute UTC instant (`time_zone: \"Etc/UTC\"`), so no further zone conversion is needed."
  @spec parse_rfc3339(String.t()) :: DateTime.t()
  def parse_rfc3339(s) when is_binary(s) do
    case DateTime.from_iso8601(s) do
      {:ok, dt, _offset} -> dt
      {:error, reason} -> raise ArgumentError, "invalid RFC3339 timestamp #{inspect(s)}: #{inspect(reason)}"
    end
  end

  @doc "Render a `DateTime.t()` as RFC3339 UTC with a `Z` suffix."
  @spec to_rfc3339(DateTime.t()) :: String.t()
  def to_rfc3339(%DateTime{} = dt) do
    dt
    |> DateTime.truncate(:second)
    |> DateTime.to_iso8601()
  end
end
