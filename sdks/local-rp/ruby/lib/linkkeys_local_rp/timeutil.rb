# frozen_string_literal: true

require 'time'

module LinkkeysLocalRp
  # RFC3339 timestamp parsing shared by every module that checks freshness.
  #
  # Every "current time" in this SDK is an explicit `Time` parameter, never
  # `Time.now` read internally -- mirroring `liblinkkeys`'s discipline of
  # taking `now` as an argument so verification stays deterministic and
  # testable. The sole documented exception is `Revocation.count_valid_signers`,
  # which defaults `now` to the wall clock (with a test-only override)
  # because sibling-key validity is inherently "check right now," not a
  # value being verified against a caller-supplied instant -- see that
  # module's docs.
  module Timeutil
    module_function

    # Parse an RFC3339 timestamp into a UTC Time. Raises ArgumentError on
    # anything unparseable or lacking a timezone offset -- callers convert
    # that into their own typed error.
    def parse_rfc3339(str)
      raise ArgumentError, "timestamp is not a string: #{str.inspect}" unless str.is_a?(String)

      # Time.parse would silently accept a plain date/offset-less string as
      # local time; require an explicit offset (Z or +HH:MM/-HH:MM) so a
      # malformed wire timestamp can never quietly become "local time".
      unless str.strip.match?(/(Z|z|[+-]\d{2}:?\d{2})\z/)
        raise ArgumentError, "timestamp has no timezone offset: #{str.inspect}"
      end

      Time.iso8601(str.strip).getutc
    rescue ArgumentError
      raise
    rescue StandardError => e
      raise ArgumentError, "unparseable RFC3339 timestamp #{str.inspect}: #{e.message}"
    end

    # Render a Time as RFC3339 UTC with a Z suffix. Exact separator/
    # precision style is not wire-normative (only the parsed instant is
    # ever compared -- see design doc Wire Precision), but whole-second
    # precision is used whenever the Time carries no sub-second component,
    # matching the Rust/Python references' typical output.
    def to_rfc3339(time)
      utc = time.getutc
      utc.usec.zero? ? utc.strftime('%Y-%m-%dT%H:%M:%SZ') : utc.strftime('%Y-%m-%dT%H:%M:%S.%6NZ')
    end
  end
end
