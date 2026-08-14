# Auth SDKs

## Go

```go
import "github.com/davveo/unified-account-center/sdk/go/uac"

c := uac.New("http://127.0.0.1:8080", "app_demo", "demo_secret_change_me")
ch, _ := c.Challenge(ctx, "phone_otp", "13800138000", "login")
```

## TypeScript

```ts
import { AuthClient } from "./src/client";

const auth = new AuthClient({
  endpoint: "http://127.0.0.1:8080",
  clientId: "app_demo",
});
await auth.challenge({ method: "phone_otp", identity: "13800138000", scene: "login" });
```

## Python

```bash
cd sdk/python && python3 -m venv .venv && source .venv/bin/activate && pip install -e .
```

```python
from uac import AuthClient, JWKSVerifier

c = AuthClient("http://127.0.0.1:8080", "app_demo", "demo_secret_change_me")
ch = c.challenge("phone_otp", "13800138000", "login")
```

详见 [python/README.md](./python/README.md)。

Introspect / JWKS / Step-up / Hosted：

- `client.JWKS(ctx)` / `auth.jwks()` / `c.jwks()` → `GET /.well-known/jwks.json`
- `introspect` 需 `X-Client-Secret`
- `stepUp(accessToken, …)` → 敏感操作二次验证
- `hostedLoginURL({ redirectUri, state, codeChallenge })` → 跳转托管登录
- `exchangeCode({ code, redirectUri, codeVerifier })` → 授权码换 Token
- `listSessions(accessToken, refreshToken?)` → 设备会话
- `mfaComplete({ mfa_token, code })` → MFA 登录补全
- `mergeStart` / `mergeConfirm` → 账号合并

本地 JWKS 验签（支持 kid 双钥）：

```go
v := uac.NewJWKSVerifier("http://127.0.0.1:8080/.well-known/jwks.json", "unified-account-center")
http.Handle("/api/", v.HTTPMiddleware(yourHandler))
```

```ts
import { JWKSVerifier } from "./jwks";
const v = new JWKSVerifier("http://127.0.0.1:8080/.well-known/jwks.json", "unified-account-center");
const claims = await v.verify(accessToken);
```

```python
from uac import JWKSVerifier
v = JWKSVerifier("http://127.0.0.1:8080/.well-known/jwks.json", "unified-account-center")
claims = v.verify(access_token)
# optional ASGI: app = v.asgi_middleware(app)
```
