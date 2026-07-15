defmodule LinkkeysLocalRp.Test.Vectors do
  @moduledoc """
  Loads the shared conformance vector JSON files
  (`sdks/local-rp/conformance/`) using OTP 27+'s built-in `:json` module
  (probed available on OTP 29 — see the SDK README) rather than a
  hand-rolled JSON parser or a hex dependency like `jason`.
  """

  @conformance_dir Path.expand("../../../conformance", __DIR__)

  def conformance_dir, do: @conformance_dir

  @doc """
  Load and decode a conformance vector JSON file by filename, using OTP's
  built-in `:json.decode/1`. Normalizes JSON `null` to Elixir `nil`
  throughout the decoded tree — `:json.decode/1` maps `null` to the atom
  `:null`, not `nil` (probed explicitly; see the SDK README's "whether OTP
  :json was available" section), and every vector file's optional fields
  (`revoked_at`, `local_domain_hint`, `expected_https_base`, ...) rely on
  ordinary Elixir `nil` semantics in the tests that consume them.
  """
  def load(name) do
    path = Path.join(@conformance_dir, name)
    path |> File.read!() |> :json.decode() |> normalize_null()
  end

  defp normalize_null(:null), do: nil
  defp normalize_null(m) when is_map(m), do: Map.new(m, fn {k, v} -> {k, normalize_null(v)} end)
  defp normalize_null(l) when is_list(l), do: Enum.map(l, &normalize_null/1)
  defp normalize_null(other), do: other

  @doc "Decode a lowercase (or mixed-case) hex string to raw bytes."
  def hex(s) when is_binary(s), do: Base.decode16!(s, case: :mixed)

  @doc "Encode raw bytes to lowercase hex."
  def unhex(bin) when is_binary(bin), do: Base.encode16(bin, case: :lower)
end
