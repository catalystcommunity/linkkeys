# frozen_string_literal: true

require_relative 'test_helper'

class TestConformanceExpirations < Minitest::Test
  include ConformanceHelper

  def test_check_expirations_thresholds
    ce = expirations_vector['check_expirations']
    ce['cases'].each do |c|
      now = LinkkeysLocalRp::Timeutil.parse_rfc3339(c['now'])
      status = LinkkeysLocalRp::LocalRp.check_expirations(ce['expires_at'], now)
      assert_equal c['expected_level'], status.level, "now=#{c['now']}"
    end
  end

  def test_check_timestamps_skew_boundaries
    ct = expirations_vector['check_timestamps']
    ct['cases'].each do |c|
      now = LinkkeysLocalRp::Timeutil.parse_rfc3339(c['now'])
      valid = begin
        LinkkeysLocalRp::LocalRp.check_timestamps(ct['issued_at'], ct['expires_at'], now, ct['skew_seconds'])
        true
      rescue LinkkeysLocalRp::LocalRp::Error
        false
      end
      assert_equal c['expected_valid'], valid, c['description']
    end
  end
end
