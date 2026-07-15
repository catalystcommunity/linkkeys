defmodule LinkkeysLocalRp.Encoding do
  @moduledoc """
  Base64url (unpadded) URL-parameter helpers, used for the begin route's
  `?signed_request=` parameter and the callback redirect's
  `&encrypted_token=` parameter (Wire Precision: "URL and parameter
  conventions"). Strict: standard-alphabet input (`+`/`/`) and padded input
  (`=`) are both rejected, matching `base64ct::Base64UrlUnpadded`'s decoder
  exactly (see `sdks/local-rp/conformance/url_params.json`'s negative cases).
  """

  alias LinkkeysLocalRp.Types

  defmodule DecodeError do
    defexception message: "base64url decode failed"
  end

  @doc "Encode raw bytes as unpadded base64url."
  @spec b64url_encode(binary) :: String.t()
  def b64url_encode(data) when is_binary(data), do: Base.url_encode64(data, padding: false)

  @doc "Strict unpadded base64url decode: rejects the standard alphabet and any `=` padding present in the input string itself."
  @spec b64url_decode(String.t()) :: binary
  def b64url_decode(s) when is_binary(s) do
    if not Regex.match?(~r/^[A-Za-z0-9_-]*$/, s) do
      raise DecodeError, message: "not valid unpadded base64url: #{inspect(s)}"
    end

    case Base.url_decode64(s, padding: false) do
      {:ok, bin} -> bin
      :error -> raise DecodeError, message: "base64url decode failed: #{inspect(s)}"
    end
  end

  @doc "Encode a `SignedLocalRpLoginRequest` for the begin route's `?signed_request=` parameter."
  def signed_local_rp_login_request_to_url_param(%Types.SignedLocalRpLoginRequest{} = signed) do
    b64url_encode(Types.signed_local_rp_login_request_to_cbor(signed))
  end

  @doc "Decode a `?signed_request=` parameter value back into a `SignedLocalRpLoginRequest`."
  def signed_local_rp_login_request_from_url_param(param) do
    cbor_bytes = b64url_decode(param)
    Types.signed_local_rp_login_request_from_cbor(cbor_bytes)
  end

  @doc "Encode a `LocalRpEncryptedCallback` for the callback redirect's `&encrypted_token=` parameter."
  def local_rp_encrypted_callback_to_url_param(%Types.LocalRpEncryptedCallback{} = callback) do
    b64url_encode(Types.local_rp_encrypted_callback_to_cbor(callback))
  end

  @doc "Decode an `encrypted_token=` parameter value back into a `LocalRpEncryptedCallback`."
  def local_rp_encrypted_callback_from_url_param(param) do
    cbor_bytes = b64url_decode(param)
    Types.local_rp_encrypted_callback_from_cbor(cbor_bytes)
  end
end
