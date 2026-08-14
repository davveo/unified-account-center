# 统一账户中台 · 功能与实现地图

> 梳理当前已落地能力与背后实现逻辑。主轴：`internal/server/router.go` → `service/*` → `adapter` / `repository`（MySQL + Redis）。

相关文档：

| 文档 | 内容 |
|------|------|
| [integration.md](./integration.md) | 业务方接口约定与错误码 |
| [gateway.md](./gateway.md) | 网关 JWKS / introspect / userinfo |
| [operations.md](./operations.md) | 操作手册入口（管理端 / 终端用户） |

---

## 1. 整体定位

统一账户中台负责：

- 给业务应用签发登录与 Token
- 给终端用户提供账户自助
- 给运营提供多租户 / 应用治理
- 给网关提供验票与强退旁路

### 三端分工

| 入口 | 角色 | 说明 |
|------|------|------|
| `/login` | 业务接入 / 托管登录 | 按应用 `allowed_methods` 渲染登录方式；邀请码；SSO；强制改密跳转 |
| `/account` | C 端用户自助 | 资料、改密、绑定、MFA、Passkey、会话、通知偏好、合并账号 |
| `/admin` | 运营治理 | 应用 / 租户 / 用户 / 审计 / Webhook / JWT / RBAC 等 |
| `/docs` | 开发者 | OpenAPI / Swagger UI |

网关侧使用 `client_secret` 调用：`introspect` / `token-check` / `revoke`。

---

## 2. 分层架构

| 层级 | 内容 |
|------|------|
| 入口面 | `/login` · `/account` · `/admin` · `/docs` |
| API | `/api/v1/auth/*`（C 端 / 网关）· `/api/v1/admin/*`（运营）· OIDC Discovery / JWKS |
| 服务层 | `AuthService` · `AdminService` · OAuth / SAML / MFA / Passkey · Webhook Bus |
| 适配器 | SMS / Email / Captcha / OAuth Provider · Redis · MySQL · RocketMQ（可选） |

---

## 3. 主登录链路（核心逻辑）

```
Challenge → Login → (可选 MFA) → issueTokens → Hosted Code → /token 换票
                         ↓
              受保护 API（UserAuth）
```

| 步骤 | 做什么 |
|------|--------|
| **1. Challenge** | OTP 发码：校验应用允许的登录方式 → Captcha → 租户 / IP / 身份日限额 → SMS / Email 适配器 |
| **2. Login** | Authenticator 验身份 → 解析 / 注册用户 → 风控 / MFA → `issueTokens`（access + refresh + **id_token**） |
| **3. Hosted 回跳** | 签发短时 hosted code → 业务端 `POST /token` 换票（可强制 PKCE） |
| **4. 受保护 API** | `UserAuth`：验 JWT → jti / 用户黑名单 → `uv` 版本 → `mcp` 强制改密白名单 |

关键代码：

- 路由：`internal/server/router.go`
- 登录签发：`internal/service/auth_service.go`（`Login` / `issueTokens`）
- 中间件：`internal/middleware/middleware.go`（`UserAuth` / `ClientAuth`）
- 托管页：`web/hosted/*` · `internal/service/hosted.go`

---

## 4. 功能点一览

| 能力 | 做什么 | 实现落点 | 面向 |
|------|--------|----------|------|
| 登录方式 | 手机/邮箱 OTP、密码、OAuth、Passkey、SAML | `authenticator/*` + `oauth` + `webauthn` + `saml` | C |
| 托管登录 | 按应用渲染方法；邀请码；SSO 发现；强制改密跳转 | `web/hosted` + `hosted.go` | C |
| Token | Access JWT + Refresh 轮换 + id_token + revoke / introspect | `jwtutil` + `issueTokens` | C / 网关 |
| OIDC | Discovery、JWKS、userinfo、end_session | `oidc.go` + `/.well-known/*` | C / 网关 |
| 会话设备 | 列会话、踢设备、退出其他设备 | RefreshToken + sessions API | C |
| 绑定解绑 | 绑定 OTP/OAuth；解绑需 step-up | `Bind` / `Unbind` + `stepup` | C |
| 改密 / 重置 | step-up 设密；过期强制改密；密码历史；重置 OTP | `SetPassword` + `PasswordHistory` | C |
| MFA TOTP | setup / enable / disable；登录二次验证；备份码 | `mfa.go` | C |
| Passkey | 注册 / 登录 WebAuthn；列表删除 | `webauthn.go` | C |
| 账号合并 | 自助 merge start/confirm；后台强制合并 | `merge.go` + account / admin UI | C + 管理 |
| 通知 | 站内通知；邮件/短信登录提醒；用户偏好开关 | `notifications` + `User` prefs | C |
| 资料 | `PATCH /me` 改 display_name / avatar | `UpdateProfile` + `/account` | C |
| Captcha | mock / turnstile / recaptcha / geetest / yidun | `adapter/captcha` | C |
| 多租户 | Tenant、应用归属、配额（应用数 / 日 OTP） | `tenant.go` + quota webhook | 管理 |
| 企业 SSO | 域名 IdP；discover；SAML metadata / ACS / SLO | `sso.go` + `saml.go` | C + 管理 |
| 邀请入驻 | 邀请码 + 魔法链接邮件；入驻审批 | `invite.go` | 管理 → C |
| RBAC | 角色分级；写 / 管路由隔离；租户过滤 | `rbac.go` + `AdminRequire` | 管理 |
| 应用治理 | CORS / 回调、主题、require_mfa、密码天数、密钥轮换 | `admin_ops` + `App` 字段 | 管理 |
| 用户治理 | 建户 / CSV、禁用、强退、导出、匿名化、解锁 | `admin_compliance` | 管理 |
| 审计 | `request_id` / `jti` / `device_id`；检索导出 | `AuditLog` + admin audits | 管理 |
| Webhook | 重试死信；试投递 / 重放；配额告警 | `pkg/webhook` | 管理 |
| JWT 钥 | kid 双钥滚动（旧钥只验不签） | `jwtutil` + admin jwt-keys | 管理 |
| 短信热更 | mock / mq / 云厂商热切换 | `sms.HotSender` | 管理 |
| 可观测 | healthz / readyz / metrics / tracing | `observability` + `tracing` | 运维 |

---

## 5. 关键实现逻辑

### 5.1 签发与强退

- `issueTokens` 写入 access `jti`、`device_id`、`mcp`（强制改密）、`uv`（用户会话版本），并签发 OIDC `id_token`
- `ForceLogout`：撤销 refresh → `BumpUserVersion` → 用户级 access 黑名单
- 网关通过 `introspect` / `token-check` 感知失效，实现秒级强退

### 5.2 强制改密闭环

1. 密码超龄（全局 `password.max_age_days` 或应用 `password_max_age_days`）
2. 登录签发的 Token 带 `mcp` claim，响应含 `must_change_password`
3. `UserAuth` 拦截非白名单路径（仅放行改密 / step-up / me / logout / preferences 等）
4. 托管登录检测到标记后跳转 `/account` 强制改密（过期场景可跳过 step-up）
5. 改密成功后 bump `uv`，旧 Token 失效，需重新登录

### 5.3 Admin 权限模型

| 级别 | 角色 | 能力 |
|------|------|------|
| **read** | viewer+ | 列表 / Dashboard / 审计只读 |
| **write** | operator+ | 应用改写、用户建户/强退、邀请、Webhook 等 |
| **admin** | tenant_admin+ | 租户、IdP、角色分配、JWT 轮换、短信通道、OAuth Provider |

- `X-Admin-Token` 或 `platform_admin` JWT：全部能力，可跨租户
- 非平台超管：`AdminTenantFilter` 强制租户范围，列表 / 创建不可跨租户窥探

路由分组见 `internal/server/router.go` 中 `AdminRequire("write"|"admin")`。

### 5.4 登录通知

- 新设备登录 → **站内通知**（`UserNotification`）始终写入
- 邮件 / 短信：需 **全局配置**（`notify_login_email` / `notify_login_sms`）**且** 用户偏好（`PrefNotifyEmail` / `PrefNotifySMS`）同时为真
- C 端 `/account`「通知」Tab 可开关偏好；API：`GET/PATCH /api/v1/auth/preferences`

### 5.5 账号合并（两套入口）

| 入口 | API | 说明 |
|------|-----|------|
| C 端 `/account`「合并账号」 | `POST /api/v1/auth/merge/start\|confirm` | 用户验证对方身份后自助合并 |
| 管理端用户列表「合并入」 | `POST /api/v1/admin/users/merge` | 运营强制合并 |

---

## 6. Auth API 分组（速查）

| 分组 | 鉴权 | 典型接口 |
|------|------|----------|
| Public | `X-Client-Id` | challenge / login / OAuth / SAML / Passkey login / refresh |
| Server | Client + Secret | introspect / token-check / token / revoke |
| User | Client + Bearer | me / password / sessions / MFA / Passkey / merge / notifications |
| OIDC User | Bearer only | userinfo |

---

## 7. 配置要点（节选）

见 `configs/config.yaml`：

- `password.max_age_days` / `history_count` / `notify_login_*`
- `captcha.provider`：mock | turnstile | recaptcha | geetest | yidun
- `oauth.providers`：github / google / apple / dingtalk / feishu / wechat / wecom 等
- `sms` / `email`：mock | mq | aliyun | tencent
- 应用级：`require_mfa`、`password_max_age_days`、`cors_origins`、`redirect_uris`（管理后台可改）

---

## 8. 维护说明

本文档随能力演进更新；若与代码不一致，以 `internal/server/router.go` 及对应 `service` 实现为准。
