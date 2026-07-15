"""dns.json: `_linkkeys` / `_linkkeys_apis` TXT record parsing, mirroring
`crates/liblinkkeys/src/dns.rs`'s own test cases."""

import pytest

from linkkeys_local_rp import dns as lrp_dns


def test_linkkeys_txt_valid_cases(dns_vectors):
    for case in dns_vectors["linkkeys_txt"]["valid_cases"]:
        record = lrp_dns.parse_linkkeys_txt(case["txt"])
        assert record.fingerprints == case["expected_fingerprints"], case["txt"]


def test_linkkeys_txt_invalid_cases(dns_vectors):
    for case in dns_vectors["linkkeys_txt"]["invalid_cases"]:
        with pytest.raises(lrp_dns.DnsParseError):
            lrp_dns.parse_linkkeys_txt(case["txt"])


def test_linkkeys_txt_no_record_case_is_documentation_only(dns_vectors):
    assert dns_vectors["linkkeys_txt"]["no_record_case"]["documentation_only"] is True


def test_linkkeys_apis_txt_valid_cases(dns_vectors):
    for case in dns_vectors["linkkeys_apis_txt"]["valid_cases"]:
        apis = lrp_dns.parse_linkkeys_apis_txt(case["txt"])
        assert apis.tcp == case["expected_tcp"], case["txt"]
        assert apis.https_base == case["expected_https_base"], case["txt"]


def test_linkkeys_apis_txt_invalid_cases(dns_vectors):
    for case in dns_vectors["linkkeys_apis_txt"]["invalid_cases"]:
        with pytest.raises(lrp_dns.DnsParseError):
            lrp_dns.parse_linkkeys_apis_txt(case["txt"])


def test_default_tcp_port(dns_vectors):
    assert dns_vectors["default_tcp_port"] == lrp_dns.DEFAULT_TCP_PORT
