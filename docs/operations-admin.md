# 操作手册 · 管理员版

面向运营 / 平台管理员：如何通过管理后台与 Admin API 配置与排障。

终端用户侧操作见 [operations-user.md](./operations-user.md)；业务接入见 [integration.md](./integration.md)。

---

## 1. 进入管理后台

1. 打开：`http://<host>:8080/admin/`
2. **未登录会停留在登录页**，无法看到控制台内容
3. 任选一种方式登录：
   - **管理 Token**：填写 `configs/config.yaml` → `admin.token`（请求头等价于 `X-Admin-Token`）
   - **管理员账号**：手机号/邮箱 + 密码（账号须具备 `platform_admin` / `tenant_admin` / `operator` / `viewer`）
4. 登录成功后进入控制台；左下角显示当前会话，可 **退出登录**
5. 会话保存在浏览器本地；失效或 401 会自动退回登录页

API：

```http
POST /api/v1/admin/login
{"mode":"token","token":"admin-dev-token"}

POST /api/v1/admin/login
{"mode":"password","method":"phone_password","identity":"13800138000","password":"***","tenant_id":"default"}

GET /api/v1/admin/me
X-Admin-Token: ***
# 或 Authorization: Bearer <access_token>
```

也可继续用带管理角色的用户 JWT 直接调用管理 API（见第 10 节）。

---

## 2. 应用凭证

### 2.1 创建应用

1. **应用凭证** → 填写名称、`tenant_id`、登录方式、Redirect URIs
2. 「创建并生成凭证」→ 记下 `client_id` / `client_secret`

### 2.2 查看密钥

- 默认遮罩，点 **查看** / **复制**
- 旧应用提示「仅存哈希」：先 **轮换密钥** 后再查看

### 2.3 常用操作

| 操作 | 说明 |
|------|------|
| 停用 / 启用 | 停用后该应用无法登录 |
| 改方式 | 修改 `allowed_methods` |
| 主题 | 托管登录页标题 / Logo / 主题色 / 强制 PKCE |
| 轮换密钥 | 旧 secret 立即失效，并踢掉该应用 refresh |
| 托管登录 | 预览 `/login?client_id=...` |

### 2.4 API

```http
POST /api/v1/admin/apps
X-Admin-Token: ***
{"name":"商城","tenant_id":"default","allowed_methods":["phone_otp","email_otp"],"redirect_uris":["https://app.example.com/callback"]}

GET /api/v1/admin/apps/:client_id/secret
X-Admin-Token: ***
```

---

## 3. 用户与会话

| 后台操作 | 说明 |
|----------|------|
| 用户管理 → 会话 | 查看活跃设备 |
| 强制下线 | 吊销该用户全部 refresh |
| 重置 MFA | 用户丢失 Authenticator / 备份码时 |
| 风控解锁 | 解除 identity / IP 锁定 |
| 合并入 | 人工将 `source_user_id` 并入目标用户 |

```http
POST /api/v1/admin/users/:user_id/reset-mfa
POST /api/v1/admin/risk/unlock
{"kind":"id","key":"13800138000"}

POST /api/v1/admin/users/merge
{"target_user_id":"u_目标","source_user_id":"u_来源"}
```

---

## 4. 多租户

**租户管理 → 新建 / 编辑**：

| 字段 | 含义 |
|------|------|
| max_apps | 应用数量上限 |
| daily_otp_limit | 租户日发码上限 |
| force_sso | 强制企业 SSO（禁 OTP/密码） |
| disable_local_password | 禁用本地密码 |
| sso_domains | 企业邮箱域名 |

创建应用时填 `tenant_id`；超额会失败。列表可筛选：

```http
GET /api/v1/admin/apps?tenant_id=acme
GET /api/v1/admin/audits?tenant_id=acme&limit=50
```

---

## 5. 企业 SSO

1. **对接渠道** 配好 OAuth Provider
2. **租户管理 → 新增域名路由**：

```http
PUT /api/v1/admin/enterprise-idps
{
  "tenant_id": "acme",
  "domain": "acme.com",
  "provider": "github",
  "jit_enabled": true
}
```

开启 `force_sso` 后，该租户下 OTP/密码会被拒绝，用户须走企业 SSO。SAML 暂未实现。

---

## 6. 邀请码

适用：`auto_register=false`，指定人免审批开通。

**邀请 / 入驻 → 创建邀请**，或：

```http
POST /api/v1/admin/invites
{
  "tenant_id": "default",
  "client_id": "app_demo",
  "max_uses": 1,
  "expire_in": 604800,
  "email": "user@example.com",
  "phone": "",
  "note": "给张三"
}
```

- 将返回的 `code` 发给用户（可复制 / 吊销）
- 用户登录 body 带 `invite_code`（见用户版）
- 若限定了 email/phone，用户必须匹配

| 方式 | 何时用 |
|------|--------|
| 邀请码 | 已知目标，免审批开通 |
| 入驻审批 | 无码自助申请，运营事后审批 |

---

## 7. 入驻审批

1. 应用关闭「允许自动注册」
2. 新用户无邀请码登录 → 产生 pending 申请（用户侧见 `40320`）
3. **邀请 / 入驻 → 入驻审批** → **通过 / 拒绝**
4. 通过后用户再登录即可

```http
GET  /api/v1/admin/join-requests?status=pending
POST /api/v1/admin/join-requests/:request_id/review
{"decision":"approve"}
```

---

## 8. 管理员建用户

**邀请 / 入驻 → 创建用户**，或：

```http
POST /api/v1/admin/users
{
  "tenant_id": "default",
  "phone": "13800138000",
  "display_name": "张三",
  "password": "",
  "roles": ["user"]
}
```

密码为空时返回 `temp_password`（仅一次）；请安全下发。应用需启用对应密码登录方式。

---

## 9. 风控运维

系统行为（无需配置即可生效）：

- 连续登录失败锁定 identity / IP
- 新设备 + 已开 MFA → 二次验证
- 告警可推送到 `risk.alert_webhook_url`

解锁：用户管理 → **风控解锁**（`kind=id|ip`）。

---

## 10. 角色权限（RBAC）

| 角色 | 能力 |
|------|------|
| `platform_admin` | 平台全量管理 |
| `tenant_admin` | 租户管理 |
| `operator` | 读写用户等运营 |
| `viewer` | 只读 |
| `user` | 普通用户 |

**角色权限** 页分配，或：

```http
POST /api/v1/admin/roles/assign
{"user_id":"u_xxx","tenant_id":"default","role":"operator"}

POST /api/v1/admin/roles/revoke
{"user_id":"u_xxx","tenant_id":"default","role":"operator"}
```

管理 API 鉴权：

1. `X-Admin-Token`（等同超管）
2. 或 `Authorization: Bearer <含管理角色的 access_token>`

---

## 11. 渠道测试与审计

**渠道测试**：选应用 → 发码 / 密码 / OAuth → 看响应。开发环境验证码在日志 `[mock-sms]` / `[mock-email]`。

**审计日志**：按 `user_id` / `action` / `tenant_id` / 日期查询。可 **导出 CSV**，或 **导出到对象存储**（写入 `export.dir`，默认 `data/exports`，再 `GET /api/v1/admin/exports/:filename` 下载）。

常见 action：`login_ok`、`login_fail`、`mfa_*`、`merge_*`、`admin_rotate_secret`、`admin_reveal_secret`、`admin_oauth_hot_reload`、`admin_sms_hot_reload`、`admin_export_audits`、`otp_limit_alert`。

```http
GET /api/v1/admin/audits?user_id=&action=&from=2026-01-01&to=2026-01-31&limit=50
GET /api/v1/admin/audits/export?persist=1&from=2026-01-01
```

---

## 12. 运营概览（Dashboard）

后台首页 **运营概览**：

- 进程级：登录成功率、OTP 发送量、刷短信告警次数、当前短信通道
- 近 24h 审计聚合：成功/失败登录、发码量
- OTP 相关告警列表

```http
GET /api/v1/admin/dashboard
```

Prometheus：`GET /metrics`（含 `uac_login_total`、`uac_otp_sent_total`、`uac_otp_limit_hits_total`）。

---

## 13. 短信 / OAuth 热更新

### OAuth Provider

**对接渠道** 或 API `PUT /api/v1/admin/oauth-providers` 更新 `client_id` / `client_secret` 等，立即生效，写审计 `admin_oauth_hot_reload`。

### 短信通道

**对接渠道 → 短信通道热更新**：在 `mock` / `mq` 间切换（MQ 需配置启用），写审计 `admin_sms_hot_reload`。

```http
GET /api/v1/admin/sms-channel
PUT /api/v1/admin/sms-channel
{"provider":"mock"}
```

### 密钥轮换审计

应用 **轮换密钥** / **查看密钥** 分别写 `admin_rotate_secret` / `admin_reveal_secret`（含操作者）。

---

## 14. OIDC / UserInfo（供网关）

- Discovery：`GET /.well-known/openid-configuration`
- UserInfo：`GET /api/v1/auth/userinfo`（Bearer）
- 详见 [gateway.md](./gateway.md)

---

## 15. 常见问题（管理侧）

**查看 secret 提示仅哈希？**  
轮换一次密钥即可；新应用默认可查看。

**用户邀请码仍 40320？**  
检查过期/用尽、邮箱手机限定、`client_id`/`tenant_id`、字段名是否为 `invite_code`。

**强制 SSO 后本地发码失败？**  
预期行为；引导用户企业 SSO。

**Passkey 注册失败？**  
核对服务端 `webauthn.rp_id` / `rp_origins` 与访问域名一致。

**合并后源账号登不进去？**  
预期：源会话已吊销，身份已挂到目标 `user_id`。

**切换短信 mq 失败？**  
需 `mq.enabled=true` 且生产者可用。

---

## 相关文档

| 文档 | 内容 |
|------|------|
| [operations-user.md](./operations-user.md) | 终端用户操作 |
| [integration.md](./integration.md) | 业务方接入与错误码 |
| [gateway.md](./gateway.md) | 网关 JWKS / introspect / userinfo |
| [../README.md](../README.md) | 快速启动 |
