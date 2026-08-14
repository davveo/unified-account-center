"""JWKS local JWT verification (kid-aware, dual-key rotation)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

import jwt
from jwt import PyJWKClient


@dataclass
class AccessClaims:
    """Access JWT claims aligned with UAC."""

    uid: str = ""
    cid: str = ""
    tid: str = ""
    roles: list[str] | None = None
    scope: str | None = None
    iss: str | None = None
    exp: int | None = None
    sub: str | None = None
    jti: str | None = None
    raw: dict[str, Any] | None = None

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> AccessClaims:
        return cls(
            uid=str(payload.get("uid", "")),
            cid=str(payload.get("cid", "")),
            tid=str(payload.get("tid", "")),
            roles=payload.get("roles"),
            scope=payload.get("scope"),
            iss=payload.get("iss"),
            exp=payload.get("exp"),
            sub=payload.get("sub"),
            jti=payload.get("jti"),
            raw=payload,
        )


class JWKSVerifier:
    """Fetch & cache JWKS; verify RS256 access tokens by kid."""

    def __init__(
        self,
        jwks_url: str,
        issuer: str = "",
        *,
        cache_ttl: float = 300.0,
    ) -> None:
        self.jwks_url = jwks_url
        self.issuer = issuer
        self.cache_ttl = cache_ttl
        self._jwk_client = PyJWKClient(jwks_url, cache_keys=True, lifespan=cache_ttl)

    def refresh(self) -> None:
        """Force-refresh JWKS cache."""
        self._jwk_client.fetch_data()

    def verify(self, token: str) -> AccessClaims:
        signing_key = self._jwk_client.get_signing_key_from_jwt(token)
        options: dict[str, Any] = {"verify_aud": False}
        kwargs: dict[str, Any] = {"algorithms": ["RS256"]}
        if self.issuer:
            kwargs["issuer"] = self.issuer
        else:
            options["verify_iss"] = False
        payload = jwt.decode(
            token,
            signing_key.key,
            options=options,
            **kwargs,
        )
        return AccessClaims.from_payload(payload)

    def asgi_middleware(self, app: Callable[..., Any]) -> Callable[..., Any]:
        """Minimal ASGI middleware: require Bearer, attach scope['uac_claims']."""

        async def middleware(scope: dict[str, Any], receive: Any, send: Any) -> None:
            if scope["type"] != "http":
                await app(scope, receive, send)
                return

            headers = {
                k.decode().lower(): v.decode()
                for k, v in scope.get("headers", [])
            }
            auth = headers.get("authorization", "")
            if not auth.startswith("Bearer "):
                await _send_json(send, 401, {"message": "unauthorized"})
                return
            try:
                claims = self.verify(auth[7:])
            except Exception:
                await _send_json(send, 401, {"message": "invalid token"})
                return
            scope = {**scope, "uac_claims": claims}
            await app(scope, receive, send)

        return middleware


async def _send_json(send: Any, status: int, body: dict[str, Any]) -> None:
    import json

    raw = json.dumps(body).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [[b"content-type", b"application/json"]],
        }
    )
    await send({"type": "http.response.body", "body": raw})
