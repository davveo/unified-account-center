# Unified Account Center — Python SDK

Minimal Python client for the Unified Account Center auth APIs.

## Install

```bash
cd sdk/python
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```python
from uac import AuthClient, JWKSVerifier

c = AuthClient("http://127.0.0.1:8080", "app_demo", "demo_secret_change_me")
ch = c.challenge("phone_otp", "13800138000", "login")

# Hosted login + code exchange
url = c.hosted_login_url("https://app.example.com/callback", state="xyz")
tokens = c.exchange_code(code, "https://app.example.com/callback", code_verifier=verifier)

# Local JWKS verify
v = JWKSVerifier("http://127.0.0.1:8080/.well-known/jwks.json", "unified-account-center")
claims = v.verify(access_token)
```

## API surface

| Method | Notes |
|--------|--------|
| `list_methods` / `challenge` / `login` | Password / OTP login flow |
| `refresh` / `introspect` / `logout` | Token lifecycle |
| `userinfo` / `me` | Current user |
| `jwks` | `GET /.well-known/jwks.json` |
| `step_up` | Sensitive step-up |
| `hosted_login_url` / `exchange_code` | Hosted login + PKCE |
| `list_sessions` / `mfa_complete` | Sessions & MFA |
| `merge_start` / `merge_confirm` | Account merge |
| `JWKSVerifier.verify` / `asgi_middleware` | Local RS256 verify |

`introspect` / `exchange_code` require `client_secret` (`X-Client-Secret`).
