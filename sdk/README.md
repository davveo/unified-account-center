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

Introspect / JWKS / Step-up：

- `client.JWKS(ctx)` / `auth.jwks()` → `GET /.well-known/jwks.json`
- `introspect` 需 `X-Client-Secret`
- `stepUp(accessToken, …)` → 敏感操作二次验证
