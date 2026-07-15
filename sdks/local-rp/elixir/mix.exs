defmodule LinkkeysLocalRp.MixProject do
  use Mix.Project

  def project do
    [
      app: :linkkeys_local_rp,
      version: "0.1.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_paths: ["test"],
      elixirc_paths: elixirc_paths(Mix.env())
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto, :ssl, :inets, :public_key]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Zero hex dependencies, by design (design doc's Elixir language-matrix
  # row): OTP's :crypto covers Ed25519/X25519/AES-256-GCM/ChaCha20-Poly1305,
  # HKDF is hand-rolled over :crypto.mac(:hmac, :sha256, ...), :ssl covers
  # TLS pinning, :inet_res covers DNS TXT lookups, and OTP 27+'s built-in
  # :json module parses the conformance vector JSON in tests.
  defp deps do
    []
  end
end
