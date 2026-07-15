# frozen_string_literal: true

require_relative 'test_helper'

class TestConformanceDns < Minitest::Test
  include ConformanceHelper

  def test_default_tcp_port
    assert_equal dns_vector['default_tcp_port'], LinkkeysLocalRp::Dns::DEFAULT_TCP_PORT
  end

  def test_linkkeys_txt_valid_cases
    dns_vector['linkkeys_txt']['valid_cases'].each do |c|
      record = LinkkeysLocalRp::Dns.parse_linkkeys_txt(c['txt'])
      assert_equal c['expected_fingerprints'], record.fingerprints
    end
  end

  def test_linkkeys_txt_invalid_cases
    dns_vector['linkkeys_txt']['invalid_cases'].each do |c|
      assert_raises(LinkkeysLocalRp::Dns::DnsParseError, c['name']) { LinkkeysLocalRp::Dns.parse_linkkeys_txt(c['txt']) }
    end
  end

  def test_linkkeys_apis_txt_valid_cases
    dns_vector['linkkeys_apis_txt']['valid_cases'].each do |c|
      apis = LinkkeysLocalRp::Dns.parse_linkkeys_apis_txt(c['txt'])
      if c['expected_tcp'].nil?
        assert_nil apis.tcp, c['name']
      else
        assert_equal c['expected_tcp'], apis.tcp, c['name']
      end
      if c['expected_https_base'].nil?
        assert_nil apis.https_base, c['name']
      else
        assert_equal c['expected_https_base'], apis.https_base, c['name']
      end
    end
  end

  def test_linkkeys_apis_txt_invalid_cases
    dns_vector['linkkeys_apis_txt']['invalid_cases'].each do |c|
      assert_raises(LinkkeysLocalRp::Dns::DnsParseError, c['name']) do
        LinkkeysLocalRp::Dns.parse_linkkeys_apis_txt(c['txt'])
      end
    end
  end

  def test_no_record_case_is_documentation_only
    # The "no record" case documents DNS-lookup-returns-nothing, not a
    # parser input -- nothing to parse here; the resolver seam itself must
    # treat absence as untrusted (exercised in the flow tests via
    # FakeDnsResolver raising for unknown names).
    assert_nil dns_vector['linkkeys_txt']['no_record_case']['txt']
    assert dns_vector['linkkeys_txt']['no_record_case']['documentation_only']
  end
end
