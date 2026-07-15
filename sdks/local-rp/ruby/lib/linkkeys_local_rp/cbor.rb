# frozen_string_literal: true

module LinkkeysLocalRp
  # Hand-written canonical/deterministic CBOR encoder+decoder.
  #
  # There is no csilgen Ruby target yet (a request has been filed — see
  # ~/repos/catalystcommunity/csilgen/docs/csilgen-requests/), so this module
  # is a byte-for-byte port of the generated Python SDK's
  # `linkkeys_local_rp/generated/codec.py` core encoder (~150 hand-written
  # lines there; this file is the same algorithm). It is a *definite-length*,
  # canonical CBOR implementation: no indefinite-length ("streaming") items
  # are ever produced or accepted, floats always encode as 64-bit doubles,
  # and map keys are emitted in the caller-supplied Hash's insertion order
  # (the generated per-struct encoders build that order to match each
  # struct's declared field order — see `types.rb`), not any generic
  # lexicographic sort.
  #
  # Byte-string vs text-string dispatch: Ruby has one `String` class for
  # both, distinguished only by `String#encoding`. This module uses that
  # distinction directly: a String whose encoding is `::Encoding::ASCII_8BIT`
  # ("BINARY") encodes as a CBOR byte string (major type 2); every other
  # String (typically UTF-8 or US-ASCII, i.e. anything produced by an
  # ordinary Ruby string literal, `hexdigest`, `unpack1("H*")`, etc.) encodes
  # as a CBOR text string (major type 3). This matches Ruby idiom: raw key
  # material, signatures, nonces, and ciphertext arrive as ASCII-8BIT from
  # `SecureRandom`/`OpenSSL`/`Array#pack("H*")`, while domain names, claim
  # types, hex fingerprint strings, and context strings are ordinary UTF-8
  # literals. Decoding mirrors this: CBOR byte strings decode to ASCII-8BIT
  # Ruby Strings, CBOR text strings decode to UTF-8 Ruby Strings.
  module Cbor
    # A CBOR tagged value (major type 6): a tag number wrapping a value tree.
    # Used for the RPC envelope's `payload` field, which is CBOR tag 24
    # ("encoded CBOR data item") wrapping a byte string.
    CborTag = Struct.new(:tag, :value) do
      def ==(other)
        other.is_a?(CborTag) && tag == other.tag && value == other.value
      end
    end

    class DecodeError < StandardError; end
    class EncodeError < StandardError; end

    module_function

    # Encode a Ruby value tree (Hash/Array/String/Integer/Float/true/false/
    # nil/CborTag) to canonical CBOR bytes (an ASCII-8BIT String).
    def encode(value)
      out = String.new(+'', encoding: ::Encoding::ASCII_8BIT)
      encode_value(value, out)
      out
    end

    # Decode canonical CBOR bytes into a Ruby value tree. Raises DecodeError
    # on any trailing bytes (a hard error, not silently ignored) or
    # malformed input.
    def decode(data)
      data = data.dup.force_encoding(::Encoding::ASCII_8BIT)
      value, pos = decode_value(data, 0)
      raise DecodeError, 'trailing bytes after decoding one CBOR item' unless pos == data.bytesize

      value
    rescue IndexError, ArgumentError => e
      raise DecodeError, "malformed CBOR: #{e.message}"
    end

    def encode_head(major, n, out)
      mt = major << 5
      if n < 24
        out << (mt | n)
      elsif n < 0x100
        out << (mt | 24)
        out << n
      elsif n < 0x10000
        out << (mt | 25)
        out << [n].pack('n')
      elsif n < 0x100000000
        out << (mt | 26)
        out << [n].pack('N')
      else
        out << (mt | 27)
        out << [n].pack('Q>')
      end
    end

    def encode_value(v, out)
      case v
      when nil
        out << 0xF6
      when true
        out << 0xF5
      when false
        out << 0xF4
      when Integer
        v >= 0 ? encode_head(0, v, out) : encode_head(1, -1 - v, out)
      when Float
        out << 0xFB
        out << [v].pack('G')
      when CborTag
        encode_head(6, v.tag, out)
        encode_value(v.value, out)
      when String
        if v.encoding == ::Encoding::ASCII_8BIT
          encode_head(2, v.bytesize, out)
          out << v
        else
          data = v.encode(::Encoding::UTF_8).b
          encode_head(3, data.bytesize, out)
          out << data
        end
      when Hash
        encode_head(5, v.size, out)
        # RFC 8949 §4.2.1 core deterministic encoding: map entries sorted
        # by the bytewise lexicographic order of their *encoded* keys (the
        # Java SDK's `Cbor.java` documents and implements this same rule).
        # Every hand-written struct encoder in `types.rb` already builds
        # its Hash with fields in this exact order (verified byte-for-byte
        # against every `*_cbor_hex` fixture in `sdks/local-rp/
        # conformance/`), so this sort is a no-op for them in practice --
        # it exists so the core encoder is correct on its own terms for
        # any Hash, not only the ones this SDK happens to pre-order by
        # hand (e.g. the ad hoc RPC envelope map in `rpc.rb`).
        sorted = v.each_pair.sort_by { |key, _val| encode(key) }
        sorted.each { |key, val| encode_value(key, out); encode_value(val, out) }
      when Array
        encode_head(4, v.size, out)
        v.each { |item| encode_value(item, out) }
      else
        raise EncodeError, "cannot encode value of type #{v.class}"
      end
    end

    def decode_arg(bytes, pos, low)
      case low
      when 0..23
        [low, pos + 1]
      when 24
        [bytes.getbyte(pos + 1), pos + 2]
      when 25
        [bytes.byteslice(pos + 1, 2).unpack1('n'), pos + 3]
      when 26
        [bytes.byteslice(pos + 1, 4).unpack1('N'), pos + 5]
      when 27
        [bytes.byteslice(pos + 1, 8).unpack1('Q>'), pos + 9]
      else
        raise DecodeError, 'bad CBOR argument length marker'
      end
    end

    def decode_value(bytes, pos)
      ib = bytes.getbyte(pos)
      raise DecodeError, 'unexpected end of CBOR input' if ib.nil?

      major = ib >> 5
      low = ib & 0x1F

      if major == 7
        case low
        when 20 then return [false, pos + 1]
        when 21 then return [true, pos + 1]
        when 22, 23 then return [nil, pos + 1]
        when 26 then return [bytes.byteslice(pos + 1, 4).unpack1('g'), pos + 5]
        when 27 then return [bytes.byteslice(pos + 1, 8).unpack1('G'), pos + 9]
        else raise DecodeError, 'unsupported CBOR simple value'
        end
      end

      arg, pos = decode_arg(bytes, pos, low)
      case major
      when 0
        [arg, pos]
      when 1
        [-1 - arg, pos]
      when 2
        [bytes.byteslice(pos, arg), pos + arg]
      when 3
        [bytes.byteslice(pos, arg).force_encoding(::Encoding::UTF_8), pos + arg]
      when 4
        items = []
        arg.times do
          item, pos = decode_value(bytes, pos)
          items << item
        end
        [items, pos]
      when 5
        result = {}
        arg.times do
          key, pos = decode_value(bytes, pos)
          val, pos = decode_value(bytes, pos)
          result[key] = val
        end
        [result, pos]
      when 6
        inner, pos = decode_value(bytes, pos)
        [CborTag.new(arg, inner), pos]
      else
        raise DecodeError, 'bad CBOR major type'
      end
    end
  end
end
