"""Smoke tests — no live server required."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from uac import APIError, AuthClient, JWKSVerifier
from uac.jwks import AccessClaims


def test_hosted_login_url():
    c = AuthClient("http://127.0.0.1:8080/", "app_demo", "secret")
    url = c.hosted_login_url(
        "https://app.example.com/cb",
        state="s1",
        code_challenge="cc",
        device_id="d1",
    )
    assert url.startswith("http://127.0.0.1:8080/login?")
    q = parse_qs(urlparse(url).query)
    assert q["client_id"] == ["app_demo"]
    assert q["redirect_uri"] == ["https://app.example.com/cb"]
    assert q["state"] == ["s1"]
    assert q["code_challenge"] == ["cc"]
    assert q["device_id"] == ["d1"]


def test_api_error_str():
    err = APIError(40110, "invalid credential")
    assert "40110" in str(err)
    assert err.code == 40110


def test_access_claims_from_payload():
    c = AccessClaims.from_payload(
        {"uid": "u1", "cid": "app", "tid": "t", "roles": ["user"], "iss": "uac"}
    )
    assert c.uid == "u1"
    assert c.roles == ["user"]


def test_jwks_verifier_construct():
    v = JWKSVerifier("http://127.0.0.1:8080/.well-known/jwks.json", "unified-account-center")
    assert v.issuer == "unified-account-center"
    assert v.cache_ttl == 300.0


def test_import_public_api():
    from uac import AuthClient as A
    from uac import JWKSVerifier as J

    assert A is AuthClient
    assert J is JWKSVerifier
