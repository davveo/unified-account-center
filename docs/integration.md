# 用户对接文档

本文面向需要接入「统一账户认证中台」的业务应用开发者。

## 1. 接入准备

1. 打开管理后台 `http://<host>:8080/admin/`（Header/本地保存 `X-Admin-Token`）
2. 在「应用凭证」创建应用，获得：
   - `client_id`
   - `client_secret`（**仅创建响应中返回一次明文**，请立即保存；前端禁止下发）
3. 配置启用登录方式（如 `phone_otp`、`email_password`、`oauth2`）
4. 若使用 OAuth，配置 `redirect_uri` 白名单与 Provider（GitHub 等）
5. 业务 API 统一携带用户 `Authorization: Bearer <access_token>`

也可调用管理 API：

```http
POST /api/v1/admin/apps
X-Admin-Token: admin-dev-token
Content-Type: application/json

{
  "name": "商城 App",
  "allowed_methods": ["phone_otp", "email_otp"],
  "redirect_uris": ["https://app.example.com/callback"]
}
```

查看渠道：`GET /api/v1/admin/channels`

本地演示应用（`configs/config.yaml` 启动引导）：

| 字段 | 值 |
|------|----|
| client_id | `app_demo` |
| client_secret | `demo_secret_change_me` |
| Base URL | `http://127.0.0.1:8080` |

## 2. 通用约定

### 2.1 请求头

| Header | 必填 | 说明 |
|--------|------|------|
| `X-Client-Id` | 是 | 应用 ID |
| `X-Client-Secret` | 服务端建议携带 | 携带时会校验；公网前端可不带 |
| `Authorization` | 用户态接口必填 | `Bearer <access_token>` |
| `Content-Type` | JSON 接口 | `application/json` |
| `X-Request-Id` | 否 | 链路追踪；不传则由中台生成 |

### 2.2 统一响应

```json
{
  "code": 0,
  "message": "ok",
  "request_id": "req_...",
  "data": {}
}
```

### 2.3 错误码

| code | 含义 |
|------|------|
| 0 | 成功 |
| 40001 | 参数错误 |
| 40100 | 未登录 |
| 40110 | 凭证无效（验证码/密码/Refresh） |
| 40310 | 应用无权限或凭证错误 |
| 40400 | 资源不存在 |
| 40910 | 账户冲突（已被其他用户绑定） |
| 42900 | 限流 |
| 50000 | 内部错误 |

## 3. 推荐接入流程（Token 模式）

```text
1. GET  /api/v1/auth/methods          # 动态渲染登录方式
2. POST /api/v1/auth/challenge        # 验证码类先发码
3. POST /api/v1/auth/login            # 换取 access/refresh
4. 业务请求携带 Authorization
5. access 过期后 POST /token/refresh
6. 退出 POST /logout
```

## 4. API 明细

Base path：`/api/v1/auth`

### 4.1 查询启用登录方式

`GET /methods`

响应：

```json
{
  "code": 0,
  "data": {
    "methods": ["phone_otp", "phone_password", "email_otp", "email_password", "oauth2"]
  }
}
```

### 4.2 发送挑战（验证码）

`POST /challenge`

```json
{
  "method": "phone_otp",
  "identity": "13800138000",
  "scene": "login"
}
```

`method`：`phone_otp` | `email_otp`  
`scene`：`login` | `bind` | `reset_password`

响应：

```json
{
  "code": 0,
  "data": {
    "challenge_id": "ch_xxx",
    "expire_in": 300,
    "resend_after": 60,
    "masked_target": "138****8000"
  }
}
```

### 4.3 统一登录

`POST /login`

手机验证码：

```json
{
  "method": "phone_otp",
  "identity": "13800138000",
  "credential": {
    "challenge_id": "ch_xxx",
    "otp": "123456"
  },
  "client": {
    "device_id": "optional",
    "platform": "ios"
  }
}
```

说明：是否自动注册由应用配置 `auto_register` 决定，**客户端不可覆盖**。

手机密码：

```json
{
  "method": "phone_password",
  "identity": "13800138000",
  "credential": { "password": "Passw0rd1" }
}
```

邮箱验证码/密码：将 `method` 改为 `email_otp` / `email_password`，`identity` 填邮箱。

OAuth2：

```json
{
  "method": "oauth2",
  "provider": "github",
  "credential": {
    "code": "oauth_code",
    "redirect_uri": "https://app.example.com/callback",
    "state": "从 /oauth/{provider}/start 返回的 state",
    "code_verifier": "pkce_verifier"
  }
}
```

`state` 与 `redirect_uri` 必须与 start 时一致（中台会一次性消费校验）。`redirect_uri` 须与应用白名单**精确匹配**。

成功响应（结构固定）：

```json
{
  "code": 0,
  "data": {
    "user": {
      "user_id": "u_xxx",
      "display_name": "138****8000",
      "avatar": "",
      "status": "active"
    },
    "identities": [
      { "type": "phone", "value": "138****8000", "verified": true }
    ],
    "token": {
      "access_token": "eyJ...",
      "token_type": "Bearer",
      "expire_in": 7200,
      "refresh_token": "rt_...",
      "refresh_expire_in": 2592000
    },
    "is_new_user": true
  }
}
```

说明：

- 同一手机号/邮箱再次登录会返回同一 `user_id`，不会重复建用户
- `is_new_user=true` 表示本次自动注册

### 4.4 刷新 Token

`POST /token/refresh`

```json
{ "refresh_token": "rt_..." }
```

注意：Refresh 采用**轮换**；旧 refresh 再次使用会被判定异常并失效。

### 4.5 登出

`POST /logout`  
Header：`Authorization: Bearer <access_token>`

```json
{
  "refresh_token": "rt_...",
  "all_devices": false
}
```

### 4.6 当前用户

`GET /me`  
Header：`Authorization: Bearer <access_token>`

### 4.7 绑定 / 解绑

绑定 `POST /identities/bind`（需登录）  
Body 与 login 类似，但发码 `scene` 必须为 `bind`：

```bash
# 先 challenge scene=bind
# 再 bind
curl -X POST /api/v1/auth/identities/bind \
  -H 'Authorization: Bearer ...' \
  -H 'X-Client-Id: app_demo' \
  -d '{"method":"email_otp","identity":"a@example.com","credential":{"challenge_id":"...","otp":"..."}}'
```

解绑 `POST /identities/unbind`：

```json
{
  "type": "phone",
  "value": "13800138000"
}
```

OAuth 解绑：

```json
{ "type": "oauth", "provider": "github" }
```

规则：至少保留一种可登录 Identity，否则返回 `40001`。

### 4.8 密码设置 / 重置

- 已登录设置：`POST /password/set` `{ "password": "Passw0rd1" }`
- 重置开始：`POST /password/reset/start` `{ "method":"phone_otp","identity":"13800138000" }`
- 重置确认：`POST /password/reset/confirm`

```json
{
  "method": "phone_otp",
  "identity": "13800138000",
  "challenge_id": "ch_xxx",
  "otp": "123456",
  "password": "Passw0rd1"
}
```

密码策略默认：最少 8 位，且同时包含字母与数字。

### 4.9 OAuth 辅助

`GET /oauth/{provider}/start?redirect_uri=...&state=...&code_challenge=...`

返回：

```json
{
  "authorize_url": "https://github.com/login/oauth/authorize?...",
  "state": "..."
}
```

前端跳转 `authorize_url`，第三方回调后拿 `code` + `state` 调 `/login`（`method=oauth2`）。请妥善保存 start 返回的 `state`。

`GET /oauth/{provider}/callback` 为中台回调入口（托管模式简化实现，返回 code/state）。

### 4.10 Token 内省（业务鉴权）

业务服务可用（**必须**携带 `X-Client-Id` + `X-Client-Secret`）：

```http
GET /api/v1/auth/introspect
X-Client-Id: app_xxx
X-Client-Secret: ***
Authorization: Bearer <access_token>
```

或：

```http
POST /api/v1/auth/introspect
X-Client-Id: app_xxx
X-Client-Secret: ***
Content-Type: application/json

{ "token": "..." }
```

响应：

```json
{
  "code": 0,
  "data": {
    "active": true,
    "user_id": "u_xxx",
    "client_id": "app_demo",
    "tenant_id": "default",
    "exp": 1710000000,
    "jti": "at_xxx"
  }
}
```

建议：

- 网关/BFF 校验 `active=true` 且 `client_id` 属于本应用
- 高并发可改为本地 JWT 验签（当前为 HS256，密钥由平台下发），撤销名单仍可走 introspect / 黑名单

## 5. 业务侧伪代码

### Web / App

```ts
const clientId = 'app_demo';
const base = 'http://127.0.0.1:8080/api/v1/auth';

async function loginByPhoneOTP(phone: string, otp: string, challengeId: string) {
  const res = await fetch(`${base}/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Client-Id': clientId,
    },
    body: JSON.stringify({
      method: 'phone_otp',
      identity: phone,
      credential: { challenge_id: challengeId, otp },
    }),
  });
  const body = await res.json();
  if (body.code !== 0) throw new Error(body.message);
  localStorage.setItem('access_token', body.data.token.access_token);
  localStorage.setItem('refresh_token', body.data.token.refresh_token);
  return body.data;
}
```

### 后端验票中间件（Go 示意）

```go
// 调用中台 introspect，或本地解析 JWT 后校验 aud/client_id
```

## 6. 标识规范化

| 类型 | 规则 |
|------|------|
| 手机号 | 国内 11 位自动补 `+86`，存储为 E.164 |
| 邮箱 | trim + lower |
| OAuth | `provider + subject`，不以昵称为主键 |

## 7. 安全建议

1. 前端只持有 `client_id`，`client_secret` 放服务端
2. 全站 HTTPS；密码仅 TLS 下传输
3. Access Token 短时效；Refresh 安全存储（HttpOnly Cookie 或系统钥匙串）
4. OAuth 公网客户端启用 PKCE；严格校验 `redirect_uri`
5. 发码接口叠加人机验证：配置 `captcha.enabled=true` 后，`POST /api/v1/auth/challenge` 必须传有效 `captcha_token`（mock：非空且不为 `fail`）
6. 敏感操作（解绑、设密）须先二次验证：
   ```http
   POST /api/v1/auth/step-up
   Authorization: Bearer <access_token>
   X-Client-Id: <client_id>
   {"method":"password","credential":{"password":"..."}}
   ```
   响应拿到 `step_up_token`，再带到 `unbind` / `password/set` 请求体。
7. 本地验签：`GET /.well-known/jwks.json`（RS256 公钥）；或网关调用 `POST /api/v1/auth/introspect`（需 `X-Client-Secret`）

## 7.1 管理后台能力

| 能力 | API |
|------|-----|
| 停用/改 methods | `PATCH /api/v1/admin/apps/:client_id` |
| 轮换 secret | `POST /api/v1/admin/apps/:client_id/rotate-secret` |
| 用户禁用 | `POST /api/v1/admin/users/:user_id/status` |
| 强制下线 | `POST /api/v1/admin/users/:user_id/force-logout` |
| 审计查询 | `GET /api/v1/admin/audits?user_id=&action=` |

UI：`/admin/` → 应用凭证 / 用户管理 / 审计日志。

## 7.2 运维探活

- `GET /healthz`：探测 MySQL + Redis
- `GET /metrics`：Prometheus 文本指标
- 进程收到 SIGINT/SIGTERM 后优雅退出

## 7.3 托管登录（Hosted Login）

1. 浏览器打开：
   ```
   /login?client_id=app_demo&redirect_uri=https://app.example.com/callback&state=xyz&code_challenge=...
   ```
2. 用户完成登录后，中台回跳：
   ```
   https://app.example.com/callback?code=ac_xxx&state=xyz
   ```
3. 业务服务端换 Token（需 `X-Client-Secret`）：
   ```http
   POST /api/v1/auth/token
   X-Client-Id: app_demo
   X-Client-Secret: ***
   {"grant_type":"authorization_code","code":"ac_xxx","redirect_uri":"https://app.example.com/callback","code_verifier":"..."}
   ```

应用可配置 `login_title` / `logo_url` / `theme_color` / `require_pkce`（管理后台「主题」或 `PATCH /api/v1/admin/apps/:id`）。

## 7.4 会话管理

- `GET /api/v1/auth/sessions`：当前应用下活跃设备
- `DELETE /api/v1/auth/sessions/:jti`：踢掉指定设备
- `POST /api/v1/auth/sessions/revoke-others`：退出其他设备（保留当前 `keep_jti` / `refresh_token`）
- 登录响应 `token.device_id` / `token.refresh_jti`

## 7.5 Captcha 与发码熔断

```yaml
captcha:
  enabled: true
  provider: turnstile # mock | turnstile | recaptcha
  site_key: "..."
  secret_key: "..."
otp:
  daily_limit_per_identity: 20
  daily_limit_per_ip: 50
```

## 8. 验收清单

- [ ] methods 返回与控制台配置一致
- [ ] 验证码登录成功并拿到统一 Token 结构
- [ ] 同一手机号二次登录 `user_id` 不变且 `is_new_user=false`
- [ ] 错误验证码 / 过期 / 重放被拒绝
- [ ] 绑定冲突返回 `40910`
- [ ] 解绑唯一登录方式被拒绝
- [ ] 应用 A 的 refresh 不能在应用 B 刷新成功
- [ ] introspect 可支撑业务网关鉴权
- [ ] captcha.enabled 时无 token / fail token 发码被拒
- [ ] 解绑/设密无 step_up_token 被拒
- [ ] JWKS 可下载且与 access token 验签一致
- [ ] 并发 refresh 仅一方成功；reuse 旧 refresh 吊销家族

## 9. 联系与支持

对接问题请联系平台负责人，并提供 `request_id`、`client_id`、大致时间窗口以便排查审计日志。
