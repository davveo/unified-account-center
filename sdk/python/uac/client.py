"""HTTP client for Unified Account Center auth APIs."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlencode

import httpx


class APIError(Exception):
    """Business error from UAC envelope (code != 0)."""

    def __init__(self, code: int, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"uac code={code} msg={message}")


class AuthClient:
    """Minimal auth client aligned with Go/TS SDKs."""

    def __init__(
        self,
        endpoint: str,
        client_id: str,
        client_secret: str | None = None,
        *,
        timeout: float = 15.0,
        http: httpx.Client | None = None,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self._owns_http = http is None
        self.http = http or httpx.Client(timeout=timeout)

    def close(self) -> None:
        if self._owns_http:
            self.http.close()

    def __enter__(self) -> AuthClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _headers(
        self,
        *,
        require_secret: bool = False,
        access_token: str | None = None,
        extra: dict[str, str] | None = None,
    ) -> dict[str, str]:
        h: dict[str, str] = {
            "Content-Type": "application/json",
            "X-Client-Id": self.client_id,
        }
        if require_secret and self.client_secret:
            h["X-Client-Secret"] = self.client_secret
        if access_token:
            h["Authorization"] = f"Bearer {access_token}"
        if extra:
            h.update(extra)
        return h

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Any | None = None,
        require_secret: bool = False,
        access_token: str | None = None,
    ) -> Any:
        resp = self.http.request(
            method,
            f"{self.endpoint}{path}",
            json=body,
            headers=self._headers(
                require_secret=require_secret,
                access_token=access_token,
            ),
        )
        data = resp.json()
        if data.get("code", 0) != 0:
            raise APIError(int(data.get("code", -1)), str(data.get("message", "")))
        return data.get("data")

    def list_methods(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/auth/methods")

    def challenge(
        self,
        method: str,
        identity: str,
        scene: str = "login",
        *,
        captcha_token: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "method": method,
            "identity": identity,
            "scene": scene,
        }
        if captcha_token:
            payload["captcha_token"] = captcha_token
        return self._request("POST", "/api/v1/auth/challenge", body=payload)

    def login(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/api/v1/auth/login", body=payload)

    def refresh(self, refresh_token: str) -> dict[str, Any]:
        return self._request(
            "POST",
            "/api/v1/auth/token/refresh",
            body={"refresh_token": refresh_token},
        )

    def introspect(self, token: str) -> dict[str, Any]:
        return self._request(
            "POST",
            "/api/v1/auth/introspect",
            body={"token": token},
            require_secret=True,
        )

    def logout(
        self,
        access_token: str,
        *,
        refresh_token: str | None = None,
        all_devices: bool = False,
    ) -> dict[str, Any] | None:
        body: dict[str, Any] = {"all_devices": all_devices}
        if refresh_token:
            body["refresh_token"] = refresh_token
        return self._request(
            "POST",
            "/api/v1/auth/logout",
            body=body,
            access_token=access_token,
        )

    def userinfo(self, access_token: str) -> dict[str, Any]:
        """OIDC UserInfo — returns claims directly (not envelope)."""
        resp = self.http.get(
            f"{self.endpoint}/api/v1/auth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        return resp.json()

    def me(self, access_token: str) -> dict[str, Any]:
        return self._request(
            "GET",
            "/api/v1/auth/me",
            access_token=access_token,
        )

    def jwks(self) -> dict[str, Any]:
        resp = self.http.get(f"{self.endpoint}/.well-known/jwks.json")
        resp.raise_for_status()
        return resp.json()

    def step_up(self, access_token: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            "POST",
            "/api/v1/auth/step-up",
            body=payload,
            access_token=access_token,
        )

    def hosted_login_url(
        self,
        redirect_uri: str,
        *,
        state: str | None = None,
        code_challenge: str | None = None,
        device_id: str | None = None,
    ) -> str:
        params: dict[str, str] = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
        }
        if state:
            params["state"] = state
        if code_challenge:
            params["code_challenge"] = code_challenge
        if device_id:
            params["device_id"] = device_id
        # Prefer %20 over + for spaces (match Go SDK)
        qs = urlencode(params, quote_via=quote)
        return f"{self.endpoint}/login?{qs}"

    def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        *,
        code_verifier: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        }
        if code_verifier:
            body["code_verifier"] = code_verifier
        return self._request(
            "POST",
            "/api/v1/auth/token",
            body=body,
            require_secret=True,
        )

    def list_sessions(
        self,
        access_token: str,
        *,
        refresh_token: str | None = None,
    ) -> dict[str, Any]:
        q = f"?refresh_token={quote(refresh_token)}" if refresh_token else ""
        return self._request(
            "GET",
            f"/api/v1/auth/sessions{q}",
            access_token=access_token,
        )

    def mfa_complete(
        self,
        mfa_token: str,
        code: str,
        *,
        client: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"mfa_token": mfa_token, "code": code}
        if client is not None:
            payload["client"] = client
        return self._request("POST", "/api/v1/auth/mfa/complete", body=payload)

    def merge_start(
        self,
        access_token: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            "/api/v1/auth/merge/start",
            body=payload,
            access_token=access_token,
        )

    def merge_confirm(self, access_token: str, merge_token: str) -> dict[str, Any] | None:
        return self._request(
            "POST",
            "/api/v1/auth/merge/confirm",
            body={"merge_token": merge_token},
            access_token=access_token,
        )
