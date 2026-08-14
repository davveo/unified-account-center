# Unified Account Center — 能力扩展 Todo

> 基于当前已落地能力（验证码/密码/OAuth、绑定解绑、Token 轮换、管理后台、JWKS、step-up、healthz/metrics、SDK、对抗单测）与技术方案对照整理。
> 状态：P0 / P1 / P2 已完成；P3 待排期

---

## 已具备（基线，无需重做）

- [x] phone_otp / email_otp / phone_password / email_password / oauth2
- [x] 多 Identity 绑定 / 解绑（至少保留一种登录方式）
- [x] Access JWT + Refresh 轮换与复用检测
- [x] 应用隔离（client_id）、限流、审计日志
- [x] 管理后台：应用停用 / 改 methods / 轮换 secret、用户禁用 / 强退、审计查询
- [x] captcha（mock/turnstile/recaptcha）、RS256 + JWKS、敏感操作 step-up
- [x] /healthz、优雅退出、结构化日志、/metrics
- [x] Go / TS 小 SDK、对抗性单测
- [x] **P0**：托管登录、PKCE/微信企微、会话设备管理、发码日熔断
- [x] **P1**：MFA/TOTP、Passkey、账号合并、轻量风控
- [x] **P2**：多租户、企业 SSO、邀请入驻、轻量 RBAC

---

## P0｜马上能抬产品完整度

### 1. 托管登录页（Hosted Login）

- [x] 中台托管统一登录 UI（按应用 `allowed_methods` 动态渲染）
- [x] 授权码托管模式：回跳 `redirect_uri?code=...` → 换 Token
- [x] 支持主题 / Logo / 文案按应用配置
- [x] 对接文档与 SDK helper（跳转 + 换码）



### 2. OAuth PKCE + 更多 Provider

- [x] 公网客户端强制 PKCE（code_verifier / code_challenge）
- [x] 微信开放平台 / 企业微信 Provider
- [x] Provider 配置热插拔（admin 可改，无需发版）
- [x] OAuth 绑定到已登录用户的完整联调用例



### 3. 会话 / 设备管理 API

- [x] `GET /api/v1/auth/sessions` 列出当前用户设备会话
- [x] `DELETE /api/v1/auth/sessions/:jti` 踢掉指定设备
- [x] 登录响应回显 `device_id`；管理后台展示在线设备
- [x] 用户侧「退出其他设备」能力



### 4. 真实 Captcha 适配器

- [x] 接入 Turnstile / reCAPTCHA / 国内滑块之一
- [x] 配置切换 `captcha.provider`，保留 mock 便于测试
- [x] IP + identity 双维短信熔断与日额度告警
- [x] challenge 接口在 enabled 时强制校验并写入审计

---



## P1｜安全与账户体验



### 5. MFA / TOTP

- [x] 启用/绑定 TOTP（写满已预留的 `credentials.mfa_secret`）
- [x] 登录可选二因子；高风险操作强制 MFA
- [x] step-up 支持 `method=totp`
- [x] 备份恢复码（一次性）



### 6. Passkey / WebAuthn

- [x] 注册 / 登录 Passkey Authenticator 插件
- [x] 设备凭证列表与吊销
- [x] 与现有 challenge/login 状态机对齐



### 7. 账号合并（Identity Merge）

- [x] 绑定冲突（40910）引导合并流程
- [x] 验证双方身份 → 合并 identities → 保留目标 `user_id`
- [x] 合并后吊销被合并用户全部会话
- [x] 管理后台支持人工合并与审计



### 8. 轻量风控策略

- [x] 连续失败锁定（账号 / IP）
- [x] 异地 / 新设备触发二次验证
- [x] 设备指纹（可选）写入 refresh / audit
- [x] 短信成本熔断与运营告警 webhook

---



## P2｜企业与多租户



### 9. 多租户运营面

- [x] 租户 CRUD、租户管理员
- [x] 租户级配额（应用数、日发码量）
- [x] 租户数据隔离策略与后台筛选强化
- [x] 租户维度审计与 metrics



### 10. 企业 SSO

- [x] OIDC Enterprise（按邮箱域名路由 IdP）
- [x] SAML 2.0（可选，暂缓）
- [x] JIT 建用户与属性映射
- [x] 企业侧强制 SSO / 禁用本地密码策略



### 11. 邀请制注册

- [x] 邀请码 / 邮件邀请链路
- [x] `auto_register=false` 时的审批入驻
- [x] 管理员创建用户并下发初始凭证
- [x] 邀请过期、使用次数限制



### 12. 轻量 RBAC / Scope（可选）

- [x] 角色模型与用户角色绑定
- [x] Access Token 写入 `scope` / `roles` claim
- [x] 管理 API 按角色鉴权（替代单一 admin token）
- [x] 明确与完整 IAM 的边界（不做细粒度 ABAC）

---



## P3｜平台工程化



### 13. OpenAPI 与 OIDC Discovery

- [x] OpenAPI 3.0 规范与自动生成
- [x] `/.well-known/openid-configuration`
- [x] 标准 `userinfo` 端点
- [x] 网关对接示例更新



### 14. Webhook / 出站事件

- [x] 事件：`user.created` / `login.failed` / `identity.bound` / `user.disabled`
- [x] 签名校验、重试、死信
- [x] 管理后台配置 webhook URL



### 15. 密钥与轮换运营

- [x] Admin token / Client secret 进 KMS 或环境变量
- [x] JWT `kid` 双钥滚动（旧钥只验不签）
- [x] 短信 / OAuth 密钥热更新
- [x] 密钥轮换操作审计



### 16. SDK 加深

- [x] Go/TS 本地 JWKS 验签中间件
- [x] 托管登录跳转 + code 换 token helper
- [ ] Java SDK（服务端验票）
- [ ] SDK 版本发布与 changelog



### 17. 可观测补强

- [x] OpenTelemetry tracing
- [x] 审计日志导出（CSV / 对象存储）
- [x] Dashboard：登录成功率、OTP 发送量、刷短信告警
- [x] `/readyz` 与深检分级（liveness vs readiness）

---



## 建议落地批次


| 批次    | 包含项                            | 目标            | 状态          |
| ----- | ------------------------------ | ------------- | ----------- |
| 下一迭代  | #1 托管登录页、#3 设备会话、#4 真实 captcha | 接入体验 + 防刷立刻可见 | ✅ 已完成（含 #2） |
| 再下一迭代 | #5–#8 TOTP MFA / Passkey / 合并 / 风控 | 安全与账户体验     | ✅ 已完成          |
| 中期    | #9–#12 多租户/企业 SSO/邀请/RBAC      | B 端与治理能力     | ✅ 已完成（含 SAML 最小 SP） |
| 长期    | #13–#17 工程化                    | 可维护性与生态对接     | ✅ 基本完成（剩 Java SDK / changelog） |


---



## 优先三选一（若资源有限）

1. ~~托管登录页~~ ✅
2. ~~设备 / 会话自助管理~~ ✅
3. ~~真实人机验证 + 短信熔断~~ ✅

P0 入口速览：

- 托管登录：`GET /login?client_id=&redirect_uri=&state=&code_challenge=`
- 换码：`POST /api/v1/auth/token`（需 `X-Client-Secret`）
- 会话：`GET/DELETE /api/v1/auth/sessions...`
- Captcha：`captcha.provider=mock|turnstile|recaptcha`
- OAuth 热更新：`PUT /api/v1/admin/oauth-providers`

P1 入口速览：

- MFA：`POST /api/v1/auth/mfa/totp/setup|enable|disable`，登录补全 `POST /mfa/complete`
- Passkey：`/passkey/register|login` + `GET/DELETE /passkeys`
- 合并：`POST /merge/start|confirm`；Admin `POST /users/merge`
- 风控：`risk.*` 配置；Admin `POST /risk/unlock`；重置 MFA `POST /users/:id/reset-mfa`

P2 入口速览：

- 租户：`POST/GET/PATCH /api/v1/admin/tenants`
- 企业 SSO：`PUT/GET /api/v1/admin/enterprise-idps`；发现 `GET/POST /api/v1/auth/sso/discover?email=`
- 邀请：`POST/GET /api/v1/admin/invites`；登录携带 `invite_code`
- 入驻审批：`auto_register=false` → `40320` + `join_request_id`；Admin `GET/POST .../join-requests`
- 建用户：`POST /api/v1/admin/users`
- RBAC：`POST /api/v1/admin/roles/assign|revoke`；JWT `roles`/`scope`；Admin 可用 Bearer 管理角色 JWT

P3（已部分落地）入口速览：

- Discovery：`GET /.well-known/openid-configuration`
- UserInfo：`GET /api/v1/auth/userinfo`
- 网关文档：`docs/gateway.md`
- Dashboard：`GET /api/v1/admin/dashboard`；后台「运营概览」
- 审计导出：`GET /api/v1/admin/audits/export`（`persist=1` 写本地对象存储）
- 短信热更新：`PUT /api/v1/admin/sms-channel`
- JWT 双钥滚动：`GET/POST /api/v1/admin/jwt-keys`（`rotate` / `retire-previous`）
- 轮换/查看密钥审计：`admin_rotate_secret` / `admin_reveal_secret` / `admin_rotate_jwt_keys`
