# 网关对接示例

本文说明业务网关 / BFF 如何校验统一账户中台签发的 Access Token。

相关能力：

- Discovery：`GET /.well-known/openid-configuration`
- JWKS：`GET /.well-known/jwks.json`
- Introspect：`GET|POST /api/v1/auth/introspect`（需 `X-Client-Id` + `X-Client-Secret`）
- UserInfo：`GET|POST /api/v1/auth/userinfo`（Bearer）

---

## 1. 推荐模式对比

| 模式 | 适用 | 延迟 | 说明 |
|------|------|------|------|
| **本地 JWKS 验签** | 高并发网关 | 低 | 缓存公钥，本地验 JWT；吊销依赖短 TTL 或黑名单旁路 |
| **Introspect** | 强一致吊销 | 较高 | 每次请求打中台；logout / 强退后立即失效 |

生产常见组合：网关 JWKS 验签 + 关键业务接口偶尔 introspect；或短 Access TTL（如 5–15 分钟）。

---

## 2. OIDC Discovery

```bash
curl -s http://127.0.0.1:8080/.well-known/openid-configuration | jq
```

关键字段：`issuer`、`jwks_uri`、`token_endpoint`、`userinfo_endpoint`、`introspection_endpoint`。

配置 `server.public_base_url` 可固定对外域名；未配置时按请求 Host 推导。

---

## 3. 标准 UserInfo

```bash
curl -s http://127.0.0.1:8080/api/v1/auth/userinfo \
  -H "Authorization: Bearer <access_token>"
```

响应示例（OIDC claims，非业务 envelope）：

```json
{
  "sub": "u_xxx",
  "name": "张三",
  "email": "a@example.com",
  "email_verified": true,
  "phone_number": "+8613800138000",
  "phone_number_verified": true,
  "tenant_id": "default",
  "roles": ["user"]
}
```

富客户端资料仍用：`GET /api/v1/auth/me`（需 `X-Client-Id`，返回脱敏 identities）。

---

## 4. Introspect 模式（网关）

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/auth/introspect \
  -H "X-Client-Id: app_demo" \
  -H "X-Client-Secret: demo_secret_change_me" \
  -H "Content-Type: application/json" \
  -d '{"token":"<access_token>"}'
```

`active=true` 时放行，并可把 `user_id` / `roles` / `tenant_id` 注入下游头。

### Nginx + auth_request（示意）

```nginx
location /_uac_introspect {
  internal;
  proxy_pass http://uac:8080/api/v1/auth/introspect;
  proxy_pass_request_body on;
  proxy_set_header Content-Type application/json;
  proxy_set_header X-Client-Id $uac_client_id;
  proxy_set_header X-Client-Secret $uac_client_secret;
}

location /api/ {
  auth_request /_uac_introspect;
  # 实际需用 lua/njs 把 Authorization 转成 introspect body
  proxy_pass http://backend;
}
```

> 生产更建议专用鉴权 sidecar / Kong 插件，而不是纯 Nginx 拼 JSON。

### Kong 伪配置

1. 对路由启用 **OpenID Connect** 或自定义 **pre-function** 调 introspect
2. 校验 `active`
3. 设置 `X-User-Id`、`X-Tenant-Id`、`X-Roles` 转发给 upstream

---

## 5. JWKS 本地验签（Go 示意）

```go
// 1. 拉取并缓存 /.well-known/jwks.json
// 2. 解析 Authorization Bearer
// 3. 用 kid 选钥，校验 iss / exp / 签名
// 4. 读取 claims: uid, cid, tid, roles, scope
```

注意：

- Access Token 的 `cid` 应与当前业务应用一致（可选强制）
- 用户 logout / Admin 强退后，仅依赖 JWT 本地验签时需等待过期；强一致请 introspect 或维护 jti 黑名单查询

---

## 6. 头约定建议

| 头 | 含义 |
|----|------|
| `Authorization: Bearer ...` | 终端用户 Access Token |
| `X-Client-Id` | 业务应用 ID（调 /me、登录等） |
| `X-Client-Secret` | 仅服务端；introspect / 换 token |
| `X-Request-Id` | 全链路追踪，中台会回写 |

下游注入（网关验票后）：

| 头 | 来源 claim |
|----|------------|
| `X-User-Id` | `uid` / introspect.`user_id` |
| `X-Tenant-Id` | `tid` |
| `X-Roles` | `roles` 逗号拼接 |

---

## 7. 验收清单

- [ ] Discovery / JWKS 可被网关拉取
- [ ] userinfo 返回 `sub`
- [ ] introspect 无效 token → `active=false`
- [ ] logout 后 introspect 立即 inactive
- [ ] 应用 A 的 token 不能用于应用 B 的需绑定 client 的接口
