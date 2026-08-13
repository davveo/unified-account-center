# 操作手册 · 终端用户版

面向最终用户 / 业务 App 开发者（用户态能力）：登录、安全设置、邀请入驻等。

管理员后台操作见 [operations-admin.md](./operations-admin.md)；完整接口约定见 [integration.md](./integration.md)。

> 多数能力由业务 App 封装；下列为中台接口行为说明，便于联调与自助排查。

---

## 1. 登录方式概览

按应用配置，可能支持：

| 方式 | 说明 |
|------|------|
| 手机 / 邮箱验证码 | 先发码再登录 |
| 手机 / 邮箱密码 | 需已设密 |
| OAuth / 企业 SSO | 跳转第三方后回跳 |
| Passkey | 本机生物识别 / 安全密钥 |
| 托管登录页 | 业务跳转 `/login?...`，完成后回业务站 |

请求需带应用 `X-Client-Id`（及服务端换码时的 `X-Client-Secret`）。

---

## 2. 托管登录页

业务推荐流程：跳转中台 → 登录 → 回跳拿 `code` → **业务服务端**换 Token。

```text
GET /login?client_id=app_demo
  &redirect_uri=https://app.example.com/callback
  &state=xyz
  &code_challenge=<S256>
  &device_id=optional
```

若已开启 MFA，页面会再要求 TOTP 或备份码，通过后才回跳。

---

## 3. 会话与设备

登录后可：

| 操作 | 接口 |
|------|------|
| 查看当前会话 | `GET /api/v1/auth/sessions` |
| 踢掉某台设备 | `DELETE /api/v1/auth/sessions/:jti` |
| 仅保留本机 | `POST /api/v1/auth/sessions/revoke-others` |

均需：`Authorization: Bearer <access_token>` + `X-Client-Id`。

---

## 4. 开启 / 关闭 MFA（TOTP）

### 开启

1. 已登录调用 `POST /api/v1/auth/mfa/totp/setup` → 用 Authenticator 扫 `otpauth_url`
2. `POST /api/v1/auth/mfa/totp/enable` `{"code":"123456"}` → **立即保存返回的备份码**（一次性）

### 关闭

先完成 step-up，再 `POST /api/v1/auth/mfa/totp/disable`。

丢失设备且无备份码时，联系管理员重置 MFA。

### 登录二次验证

1. 正常登录若返回 `code=40120`，取 `data.mfa_token`
2. 提交：

```http
POST /api/v1/auth/mfa/complete
{
  "mfa_token": "...",
  "code": "123456",
  "client": { "device_id": "web_xxx" }
}
```

`code` 可为 TOTP 或备份码（备份码用一次即作废）。

---

## 5. Passkey（通行密钥）

浏览器需支持 WebAuthn；仅当应用启用了 `passkey`。

| 步骤 | 接口 |
|------|------|
| 注册 | `register/begin` → 本机确认 → `register/finish`（需已登录） |
| 登录 | `login/begin` → 本机确认 → `login/finish` |
| 管理 | `GET /api/v1/auth/passkeys`、`DELETE .../:id` |

---

## 6. 绑定冲突与账号合并

绑定已被他人占用的手机号/邮箱时，可能返回 `40910` 且 `merge_available=true`。

自助合并（当前登录账号为**保留目标**）：

1. 验证「对方账号」的一种登录方式：

```http
POST /api/v1/auth/merge/start
Authorization: Bearer <access_token>
{
  "method": "phone_otp",
  "identity": "13900001111",
  "credential": { "challenge_id": "...", "otp": "..." }
}
```

2. 确认：

```http
POST /api/v1/auth/merge/confirm
{"merge_token":"..."}
```

合并后：对方会话失效，手机号/邮箱归属当前账号。无法自助时请联系管理员人工合并。

---

## 7. 邀请码开通

管理员给你一串 `invite_code`（如 `inv_xxxx`）时，首次登录带上即可直接开通（免审批）：

```http
POST /api/v1/auth/login
X-Client-Id: app_demo

{
  "method": "phone_otp",
  "identity": "13800138000",
  "credential": { "challenge_id": "ch_xxx", "otp": "123456" },
  "invite_code": "inv_xxxx"
}
```

注意：

- 邀请若限定邮箱/手机，必须一致
- 码可能有过期时间与使用次数
- 没有邀请码且应用不开放注册 → 见下一节

---

## 8. 等待入驻审批

应用关闭自动注册、且你**没有**邀请码时，登录可能返回：

```json
{
  "code": 40320,
  "message": "用户不存在，已提交入驻申请，等待审批",
  "data": { "join_request_id": "jr_xxx", "status": "pending" }
}
```

含义：申请已提交，请等待管理员通过后再登录。可把 `join_request_id` 发给运营催办。

---

## 9. 企业邮箱 SSO

若公司启用了企业 SSO：

1. 输入工作邮箱后，业务可调用发现接口：

```http
GET /api/v1/auth/sso/discover?email=alice@acme.com
X-Client-Id: app_demo
```

2. 按返回的 `provider` 走 OAuth / 企业登录

若企业开启「强制 SSO」，验证码 / 本地密码登录会被拒绝，请只用企业入口。

---

## 10. 管理员下发的临时密码

运营可能为你创建账号并给出临时密码：用手机号或邮箱 + 密码登录（应用需支持对应方式）。建议首次登录后尽快修改密码（若业务提供改密入口）。

---

## 11. 常见问题（用户侧）

**登录要二次验证码？**  
账号已开 MFA，或新设备触发了二次验证；用 Authenticator 或备份码完成。

**提示入驻等待审批？**  
无邀请码且需审批；联系管理员，或索取邀请码。

**邀请码无效？**  
可能过期、用尽，或与发给你的手机/邮箱不匹配。

**绑定手机提示冲突？**  
该号码已绑其他账号；走合并流程或联系管理员。

**Passkey 用不了？**  
换支持的浏览器/设备，或确认当前站点域名正确；也可改用验证码 / 密码。

**账号被锁定？**  
连续输错会被锁一段时间；等解锁或联系管理员「风控解锁」。

---

## 相关文档

| 文档 | 内容 |
|------|------|
| [operations-admin.md](./operations-admin.md) | 管理员后台操作 |
| [integration.md](./integration.md) | 完整对接与错误码 |
| [../README.md](../README.md) | 快速启动 |
