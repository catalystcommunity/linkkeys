# frozen_string_literal: true

require_relative 'test_helper'

class TestConformanceTickets < Minitest::Test
  include ConformanceHelper

  def test_ticket_sha256_matches
    tickets_vector['cases'].each do |c|
      ticket_bytes = ConformanceHelper.hex(c['ticket_hex'])
      assert_equal 32, ticket_bytes.bytesize
      assert_equal c['sha256_hex'], LinkkeysLocalRp::Crypto.fingerprint(ticket_bytes)
    end
  end
end
