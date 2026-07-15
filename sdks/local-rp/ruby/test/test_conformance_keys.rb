# frozen_string_literal: true

require_relative 'test_helper'

class TestConformanceKeys < Minitest::Test
  include ConformanceHelper

  def test_fingerprint_matches_fixed_vectors
    k = keys_vector
    %w[local_rp.signing domain_signing_key].each do |path|
      entry = path.split('.').reduce(k) { |h, part| h[part] }
      public_key = ConformanceHelper.hex(entry['public_key_hex'])
      got = LinkkeysLocalRp::Crypto.fingerprint(public_key)
      assert_equal entry['fingerprint_hex'], got, "fingerprint mismatch for #{path}"
    end
  end

  def test_fingerprint_to_from_string_round_trip
    fp = keys_vector['local_rp']['signing']['fingerprint_hex']
    assert_equal fp, LinkkeysLocalRp.fingerprint_to_string(fp)
    assert_equal fp, LinkkeysLocalRp.fingerprint_from_string(fp.upcase)

    assert_raises(LinkkeysLocalRp::Identity::Error) { LinkkeysLocalRp.fingerprint_from_string('not-a-fingerprint') }
    assert_raises(LinkkeysLocalRp::Identity::Error) { LinkkeysLocalRp.fingerprint_from_string('ab' * 31) }
  end
end
