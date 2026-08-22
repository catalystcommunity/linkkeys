from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

import pytest

from linkkeys_local_rp.begin import BeginLocalLoginConfig, BeginLoginError, begin_local_login
from linkkeys_local_rp.identity import GenerateLocalRpIdentityConfig, generate_local_rp_identity


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
KEY_MATERIAL = generate_local_rp_identity(GenerateLocalRpIdentityConfig(app_name="Test App", now=NOW))


def begin(identity: str):
    return begin_local_login(BeginLocalLoginConfig(KEY_MATERIAL, "http://localhost/callback", identity, NOW))


def test_full_login_adds_username_hint_and_bare_domain_does_not():
    redirect, pending = begin("Alice+work@ID.Example.TEST")
    assert parse_qs(urlparse(redirect.redirect_url).query)["username"] == ["Alice+work"]
    assert pending.user_domain == "id.example.test"
    redirect, _ = begin("example.test")
    assert "username" not in parse_qs(urlparse(redirect.redirect_url).query)


@pytest.mark.parametrize("identity", ["alice", "alice@@example.test", "https://example.test"])
def test_malformed_identity_is_rejected(identity):
    with pytest.raises(BeginLoginError):
        begin(identity)
