defmodule LinkkeysLocalRp.ConformanceDnsTest do
  use ExUnit.Case, async: true

  alias LinkkeysLocalRp.Dns
  alias LinkkeysLocalRp.Test.Vectors

  @dns_vectors Vectors.load("dns.json")

  test "linkkeys_txt valid cases" do
    for case_ <- @dns_vectors["linkkeys_txt"]["valid_cases"] do
      record = Dns.parse_linkkeys_txt(case_["txt"])
      assert record.fingerprints == case_["expected_fingerprints"], case_["txt"]
    end
  end

  test "linkkeys_txt invalid cases" do
    for case_ <- @dns_vectors["linkkeys_txt"]["invalid_cases"] do
      assert_raise Dns.DnsParseError, fn -> Dns.parse_linkkeys_txt(case_["txt"]) end
    end
  end

  test "linkkeys_txt no_record_case is documentation only" do
    assert @dns_vectors["linkkeys_txt"]["no_record_case"]["documentation_only"] == true
  end

  test "linkkeys_apis_txt valid cases" do
    for case_ <- @dns_vectors["linkkeys_apis_txt"]["valid_cases"] do
      apis = Dns.parse_linkkeys_apis_txt(case_["txt"])
      assert apis.tcp == case_["expected_tcp"], case_["txt"]
      assert apis.https_base == case_["expected_https_base"], case_["txt"]
    end
  end

  test "linkkeys_apis_txt invalid cases" do
    for case_ <- @dns_vectors["linkkeys_apis_txt"]["invalid_cases"] do
      assert_raise Dns.DnsParseError, fn -> Dns.parse_linkkeys_apis_txt(case_["txt"]) end
    end
  end

  test "default_tcp_port matches" do
    assert @dns_vectors["default_tcp_port"] == Dns.default_tcp_port()
  end
end
