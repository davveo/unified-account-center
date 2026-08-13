# Unified Account Center

多账户用户认证中台（Go + Gin + GORM + Redis，消息可选 RocketMQ）。

以 `user_id` 为唯一用户主键，支持同一用户绑定手机号、邮箱、OAuth 等多种 Identity，并通过统一的 `challenge` / `login` 接口收敛登录流程。

## 功能概览

| 能力 | 说明 |
|------|------|
| 手机号/邮箱验证码登录 | `phone_otp` / `email_otp` |
| 手机号/邮箱密码登录 | `phone_password` / `email_password` |
| OAuth2 登录 | `oauth2`（Provider 可配置，如 GitHub） |
| 多账户绑定/解绑 | 登录后绑定；至少保留一种登录方式 |
| Token | Access JWT + Refresh 轮换（复用检测） |
| 应用隔离 | `client_id` 维度校验 Token / Refresh |
| 限流与审计 | OTP 频控、登录/绑定等审计日志 |

## 分层架构

```text
cmd/server                 # 启动入口
configs/                   # 配置
internal/
  app/                     # 依赖组装与启动引导
  handler/                 # HTTP 接入层
  middleware/              # 请求 ID / 应用鉴权 / 用户鉴权
  service/                 # 业务编排（登录、绑定、Token）
  authenticator/           # 登录方式插件（Authenticator）
  repository/              # 数据访问
  model/                   # 数据模型
  adapter/                 # 短信 / 邮件 / OAuth 适配器
  mq/                      # RocketMQ / 本地日志 Producer
  pkg/                     # 通用工具（JWT、加密、规范化等）
  server/                  # 路由注册
docs/                      # 对接文档
```

## 快速启动（推荐：Docker 一键）

```bash
docker compose up -d --build
# 或
make docker-up
```

启动后访问：

| 入口 | 地址 |
|------|------|
| 健康检查 | http://127.0.0.1:8080/healthz |
| 管理后台 | http://127.0.0.1:8080/admin/ |
| Admin Token | `admin-dev-token` |

默认演示应用：

- `client_id`: `app_demo`
- `client_secret`: `demo_secret_change_me`

查看应用日志（验证码会打在这里）：

```bash
docker compose logs -f app
# 或 make docker-logs
```

停止：

```bash
docker compose down
# 或 make docker-down
```

Compose 包含：`mysql` + `redis` + `app`（认证中台）。

---

### 本地开发（不经过 Docker 跑 App）

依赖：Go 1.20+、MySQL 8+、Redis 6+

```bash
docker compose up -d mysql redis
go run ./cmd/server -config configs/config.yaml
```

编辑 `configs/config.yaml` 中的连接信息。Docker 内使用 `configs/config.docker.yaml`（主机名为 `mysql` / `redis`）。

### 管理后台

浏览器打开：`http://127.0.0.1:8080/admin/`

默认 Admin Token（配置项 `admin.token`）：`admin-dev-token`

功能：

1. **应用凭证**：创建 `client_id` / `client_secret`（明文仅创建时展示一次）
2. **对接渠道**：查看平台支持的登录方式及 OAuth 配置状态
3. **渠道测试**：对验证码 / 密码 / OAuth 做真实接口联调

### 最小联调（手机验证码）

开发环境短信为 mock，验证码会打印在服务日志：`[mock-sms] ... code=xxxxxx`

```bash
# 1) 发码
curl -s -X POST http://127.0.0.1:8080/api/v1/auth/challenge \
  -H 'Content-Type: application/json' \
  -H 'X-Client-Id: app_demo' \
  -d '{"method":"phone_otp","identity":"13800138000","scene":"login"}'

# 2) 登录（填入 challenge_id 与日志中的 code）
curl -s -X POST http://127.0.0.1:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -H 'X-Client-Id: app_demo' \
  -d '{"method":"phone_otp","identity":"13800138000","credential":{"challenge_id":"ch_xxx","otp":"123456"}}'
```

## 鉴权增强（已落地）

- 人机验证：`captcha.enabled=true` 时发码需传有效 `captcha_token`；`provider` 支持 `mock` / `turnstile` / `recaptcha`
- RS256 + JWKS：`GET /.well-known/jwks.json`
- 敏感操作二次验证：解绑 / 设密前先 `POST /api/v1/auth/step-up`，再携带 `step_up_token`
- 托管登录：`GET /login?client_id=...&redirect_uri=...` → 授权码回跳 → `POST /api/v1/auth/token`
- 会话管理：`GET/DELETE /api/v1/auth/sessions`，`POST /sessions/revoke-others`
- OAuth：强制 PKCE（应用 `require_pkce`）、微信/企微 Provider、Admin 热更新 Provider
- MFA/TOTP：setup/enable → 登录 `40120` → `/mfa/complete`；step-up `method=totp`；备份码
- Passkey：`/passkey/register|login` + 列表吊销；配置 `webauthn.*`
- 账号合并：绑定冲突引导 `/merge/start|confirm`；Admin 人工合并
- 风控：失败锁定、新设备 MFA、设备指纹、告警 webhook；Admin `/risk/unlock`
- 多租户：租户 CRUD / 应用与发码配额；`GET /admin/apps?tenant_id=`
- 企业 SSO：域名 → IdP（`/auth/sso/discover`），强制 SSO / 禁本地密码
- 邀请与审批：`invite_code`、入驻申请 `40320`、Admin 建用户
- RBAC：角色绑定写入 JWT `roles`/`scope`；Admin 支持 Token 或管理角色 Bearer
## SDK

见 [sdk/README.md](sdk/README.md)。

更完整的能力清单与后续迭代见 [todo.md](todo.md)。

## 测试

```bash
go test ./...
```

覆盖场景包括：验证码登录复用用户、验证码重放/错误次数、密码登录、绑定冲突、解绑保护、Refresh 轮换与并发、应用隔离、auto_register 不可绕过、OAuth state 等。

## RocketMQ（可选）

在 `configs/config.yaml` 中：

```yaml
mq:
  enabled: true
  name_server: "127.0.0.1:9876"
  producer_group: "uac_producer"
  sms_topic: "uac_sms"
  email_topic: "uac_email"

sms:
  provider: mq
email:
  provider: mq
```

开启后，OTP 发送会投递到对应 Topic，由下游消费者调用真实短信/邮件通道。

## 对接文档

详见 [docs/integration.md](docs/integration.md)。

## 许可

内部项目，按团队规范使用。
