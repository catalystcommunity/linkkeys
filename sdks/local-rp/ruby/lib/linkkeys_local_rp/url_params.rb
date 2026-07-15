# frozen_string_literal: true

require_relative 'types'

module LinkkeysLocalRp
  # Base64url (unpadded) URL-parameter helpers.
  #
  # Mirrors `crates/liblinkkeys/src/encoding.rs`'s `Base64UrlUnpadded`
  # helpers, used for the begin route's `?signed_request=` parameter and the
  # callback redirect's `&encrypted_token=` parameter (Wire Precision: "URL
  # and parameter conventions"). Strict: standard-alphabet input (`+`/`/`)
  # and padded input (`=`) are both rejected, matching
  # `base64ct::Base64UrlUnpadded`'s decoder exactly (see
  # `sdks/local-rp/conformance/url_params.json`'s negative cases).
  #
  # Hand-rolled rather than using the stdlib `base64` gem: as of Ruby 3.4,
  # `base64` is no longer a *default* gem (a bundled-but-separate gem you'd
  # have to add to the gemspec), and `[String#unpack1]`/`[Array#pack]` with
  # the `m0` directive plus a small translation table covers exactly what
  # this SDK needs with zero dependencies -- consistent with this package's
  # zero-gem-dependency target.
  module UrlParams
    B64URL_UNPADDED_RE = /\A[A-Za-z0-9_-]*\z/.freeze
    STANDARD_ALPHABET = ('A'..'Z').to_a + ('a'..'z').to_a + ('0'..'9').to_a + ['+', '/']
    URLSAFE_ALPHABET = ('A'..'Z').to_a + ('a'..'z').to_a + ('0'..'9').to_a + ['-', '_']
    STD_TO_URL = STANDARD_ALPHABET.zip(URLSAFE_ALPHABET).to_h.freeze
    URL_TO_STD = URLSAFE_ALPHABET.zip(STANDARD_ALPHABET).to_h.freeze

    class DecodeError < StandardError; end

    module_function

    def b64url_encode(data)
      standard = [data].pack('m0') # standard base64, no line wraps, WITH padding
      standard.chars.map { |c| STD_TO_URL.fetch(c, c) }.join.delete('=')
    end

    # Strict base64url decode: rejects the standard alphabet (+/) and any
    # padding (=) present in the input string itself.
    def b64url_decode(str)
      raise DecodeError, "not valid unpadded base64url: #{str.inspect}" unless B64URL_UNPADDED_RE.match?(str)

      remainder = str.length % 4
      raise DecodeError, "invalid base64url length: #{str.inspect}" if remainder == 1

      padded = str + ('=' * ((4 - remainder) % 4))
      standard = padded.chars.map { |c| URL_TO_STD.fetch(c, c) }.join
      begin
        standard.unpack1('m0')
      rescue ArgumentError => e
        raise DecodeError, "base64url decode failed: #{e.message}"
      end
    end

    def signed_local_rp_login_request_to_url_param(signed)
      b64url_encode(signed.to_cbor)
    end

    def signed_local_rp_login_request_from_url_param(param)
      cbor_bytes = b64url_decode(param)
      Types::SignedLocalRpLoginRequest.from_cbor(cbor_bytes)
    rescue DecodeError
      raise
    rescue StandardError => e
      raise DecodeError, "CBOR decode failed: #{e.message}"
    end

    def local_rp_encrypted_callback_to_url_param(callback)
      b64url_encode(callback.to_cbor)
    end

    def local_rp_encrypted_callback_from_url_param(param)
      cbor_bytes = b64url_decode(param)
      Types::LocalRpEncryptedCallback.from_cbor(cbor_bytes)
    rescue DecodeError
      raise
    rescue StandardError => e
      raise DecodeError, "CBOR decode failed: #{e.message}"
    end
  end
end
