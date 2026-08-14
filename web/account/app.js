(() => {
  const $ = (id) => document.getElementById(id);
  const qs = new URLSearchParams(location.search);
  const KEY = "uac_account_session";

  function loadSession() {
    try {
      const raw = sessionStorage.getItem(KEY);
      if (!raw) return null;
      return JSON.parse(raw);
    } catch (_) { return null; }
  }
  function saveSession(obj) {
    sessionStorage.setItem(KEY, JSON.stringify(obj || {}));
  }
  function clearSession() {
    sessionStorage.removeItem(KEY);
  }

  // 托管登录强制改密跳转带入
  if (qs.get("access_token")) {
    saveSession({
      client_id: qs.get("client_id") || "app_demo",
      access_token: qs.get("access_token"),
      force: qs.get("force") === "1",
    });
    history.replaceState({}, "", "/account/");
  }

  const sess = loadSession() || {};
  if (sess.client_id) $("clientId").value = sess.client_id;
  if (sess.access_token) $("token").value = sess.access_token;

  let challengeId = "";
  let bindChallengeId = "";
  let forceMode = sess.force || qs.get("force") === "1";

  function setMsg(el, text, ok) {
    el.textContent = text || "";
    el.className = "msg" + (text ? (ok ? " ok" : " err") : "");
  }

  async function api(path, opts = {}) {
    const token = $("token").value.trim().replace(/^Bearer\s+/i, "");
    const headers = Object.assign({
      "Content-Type": "application/json",
      "X-Client-Id": $("clientId").value.trim(),
      Authorization: "Bearer " + token,
    }, opts.headers || {});
    if (opts.device) headers["X-Device-Id"] = opts.device;
    const res = await fetch(path, { ...opts, headers });
    const body = await res.json().catch(() => ({}));
    if (!res.ok || (body.code && body.code !== 0)) {
      const err = new Error(body.message || res.statusText || "request failed");
      err.code = body.code;
      err.data = body.data;
      throw err;
    }
    return body.data;
  }

  function showJSON(el, data) {
    el.textContent = JSON.stringify(data, null, 2);
  }

  document.querySelectorAll(".tab").forEach((btn) => {
    btn.onclick = () => {
      document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b === btn));
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("active", p.dataset.panel === btn.dataset.tab));
    };
  });

  $("btnSaveSession").onclick = () => {
    saveSession({
      client_id: $("clientId").value.trim(),
      access_token: $("token").value.trim().replace(/^Bearer\s+/i, ""),
      force: forceMode,
    });
    setMsg($("pwdMsg"), "会话已保存", true);
  };
  $("btnClearSession").onclick = () => {
    clearSession();
    $("token").value = "";
    forceMode = false;
    $("forcePwd").classList.add("hidden");
    $("tabs").classList.remove("hidden");
  };

  async function refreshMe() {
    const data = await api("/api/v1/auth/me");
    showJSON($("outProfile"), data);
    const must = !!(data.token && (data.token.must_change_password || data.token.password_expired));
    if (must || forceMode) {
      forceMode = true;
      $("forcePwd").classList.remove("hidden");
      $("tabs").classList.add("hidden");
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
      $("heroHint").textContent = "密码已过期，请先完成强制改密";
    }
    return data;
  }

  $("btnMe").onclick = async () => {
    try { await refreshMe(); } catch (e) { $("outProfile").textContent = e.message; }
  };

  $("btnForcePwd").onclick = async () => {
    const p1 = $("forcePassword").value;
    const p2 = $("forcePassword2").value;
    if (!p1 || p1 !== p2) {
      setMsg($("forceMsg"), "两次密码不一致", false);
      return;
    }
    try {
      await api("/api/v1/auth/password/set", { method: "POST", body: JSON.stringify({ password: p1 }) });
      clearSession();
      setMsg($("forceMsg"), "密码已更新，请重新登录", true);
      setTimeout(() => {
        const cid = $("clientId").value.trim() || "app_demo";
        location.href = `/login?client_id=${encodeURIComponent(cid)}`;
      }, 800);
    } catch (e) {
      setMsg($("forceMsg"), e.message, false);
    }
  };

  $("btnStepUpChallenge").onclick = async () => {
    try {
      const method = $("stepUpMethod").value;
      if (method === "totp") { setMsg($("pwdMsg"), "TOTP 无需发码", true); return; }
      const data = await api("/api/v1/auth/challenge", {
        method: "POST",
        body: JSON.stringify({ method, identity: $("stepUpIdentity").value.trim(), scene: "step_up" }),
      });
      challengeId = data.challenge_id || "";
      setMsg($("pwdMsg"), "验证码已发送 " + (data.masked_target || ""), true);
    } catch (e) { setMsg($("pwdMsg"), e.message, false); }
  };

  $("btnStepUp").onclick = async () => {
    try {
      const method = $("stepUpMethod").value;
      const identity = $("stepUpIdentity").value.trim();
      const otp = $("stepUpOTP").value.trim();
      const body = { method, identity, credential: {} };
      if (method === "totp") {
        body.credential = { code: otp || identity };
      } else {
        body.credential = { challenge_id: challengeId, otp };
      }
      const data = await api("/api/v1/auth/step-up", { method: "POST", body: JSON.stringify(body) });
      $("stepUpToken").value = data.step_up_token || "";
      setMsg($("pwdMsg"), "Step-up 已获取", true);
    } catch (e) { setMsg($("pwdMsg"), e.message, false); }
  };

  $("btnSetPassword").onclick = async () => {
    try {
      await api("/api/v1/auth/password/set", {
        method: "POST",
        body: JSON.stringify({
          password: $("newPassword").value,
          step_up_token: $("stepUpToken").value.trim() || undefined,
        }),
      });
      setMsg($("pwdMsg"), "密码已更新", true);
    } catch (e) { setMsg($("pwdMsg"), e.message, false); }
  };

  $("btnBindChallenge").onclick = async () => {
    try {
      const data = await api("/api/v1/auth/challenge", {
        method: "POST",
        body: JSON.stringify({
          method: $("bindMethod").value,
          identity: $("bindIdentity").value.trim(),
          scene: "bind",
        }),
      });
      bindChallengeId = data.challenge_id || "";
      setMsg($("bindMsg"), "验证码已发送", true);
    } catch (e) { setMsg($("bindMsg"), e.message, false); }
  };
  $("btnBind").onclick = async () => {
    try {
      await api("/api/v1/auth/identities/bind", {
        method: "POST",
        body: JSON.stringify({
          method: $("bindMethod").value,
          identity: $("bindIdentity").value.trim(),
          credential: { challenge_id: bindChallengeId, otp: $("bindOTP").value.trim() },
        }),
      });
      setMsg($("bindMsg"), "绑定成功", true);
      refreshMe();
    } catch (e) { setMsg($("bindMsg"), e.message, false); }
  };
  $("btnUnbind").onclick = async () => {
    try {
      const type = $("bindMethod").value.startsWith("email") ? "email" : "phone";
      await api("/api/v1/auth/identities/unbind", {
        method: "POST",
        body: JSON.stringify({ type, value: $("bindIdentity").value.trim(), step_up_token: $("stepUpToken").value.trim() }),
      });
      setMsg($("bindMsg"), "已解绑", true);
      refreshMe();
    } catch (e) { setMsg($("bindMsg"), e.message, false); }
  };

  $("btnMFAStatus").onclick = async () => {
    try { showJSON($("outMFA"), await api("/api/v1/auth/mfa/status")); }
    catch (e) { $("outMFA").textContent = e.message; }
  };
  $("btnMFASetup").onclick = async () => {
    try { showJSON($("outMFA"), await api("/api/v1/auth/mfa/totp/setup", { method: "POST", body: "{}" })); setMsg($("mfaMsg"), "请用验证器扫描密钥后启用", true); }
    catch (e) { setMsg($("mfaMsg"), e.message, false); }
  };
  $("btnMFAEnable").onclick = async () => {
    try {
      showJSON($("outMFA"), await api("/api/v1/auth/mfa/totp/enable", { method: "POST", body: JSON.stringify({ code: $("mfaCode").value.trim() }) }));
      setMsg($("mfaMsg"), "MFA 已启用", true);
    } catch (e) { setMsg($("mfaMsg"), e.message, false); }
  };
  $("btnMFADisable").onclick = async () => {
    try {
      await api("/api/v1/auth/mfa/totp/disable", { method: "POST", body: JSON.stringify({ step_up_token: $("stepUpToken").value.trim() }) });
      setMsg($("mfaMsg"), "MFA 已关闭", true);
      $("btnMFAStatus").click();
    } catch (e) { setMsg($("mfaMsg"), e.message, false); }
  };

  function b64urlToBuf(s) {
    const pad = "=".repeat((4 - (s.length % 4)) % 4);
    const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
    const str = atob(b64);
    const buf = new ArrayBuffer(str.length);
    const view = new Uint8Array(buf);
    for (let i = 0; i < str.length; i++) view[i] = str.charCodeAt(i);
    return buf;
  }
  function bufToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let s = "";
    bytes.forEach((b) => { s += String.fromCharCode(b); });
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function loadPasskeys() {
    const list = await api("/api/v1/auth/passkeys");
    const items = list.items || list || [];
    $("passkeyList").innerHTML = items.length
      ? items.map((p) => `<div class="item"><div><strong>${p.name || "Passkey"}</strong><div class="meta">id=${p.id} · ${p.created_at || ""}</div></div>
          <button type="button" data-del="${p.id}" class="ghost">删除</button></div>`).join("")
      : `<div class="hint">暂无 Passkey</div>`;
    $("passkeyList").querySelectorAll("[data-del]").forEach((btn) => {
      btn.onclick = async () => {
        try {
          await api(`/api/v1/auth/passkeys/${btn.dataset.del}`, { method: "DELETE" });
          loadPasskeys();
        } catch (e) { setMsg($("passkeyMsg"), e.message, false); }
      };
    });
  }
  $("btnPasskeys").onclick = async () => {
    try { await loadPasskeys(); } catch (e) { setMsg($("passkeyMsg"), e.message, false); }
  };
  $("btnPasskeyReg").onclick = async () => {
    try {
      const begin = await api("/api/v1/auth/passkey/register/begin", { method: "POST", body: "{}" });
      const opts = begin.publicKey || begin.options || begin;
      const publicKey = opts.publicKey || opts;
      publicKey.challenge = b64urlToBuf(publicKey.challenge);
      publicKey.user.id = b64urlToBuf(publicKey.user.id);
      (publicKey.excludeCredentials || []).forEach((c) => { c.id = b64urlToBuf(c.id); });
      const cred = await navigator.credentials.create({ publicKey });
      const body = {
        id: cred.id,
        rawId: bufToB64url(cred.rawId),
        type: cred.type,
        response: {
          clientDataJSON: bufToB64url(cred.response.clientDataJSON),
          attestationObject: bufToB64url(cred.response.attestationObject),
        },
      };
      await api("/api/v1/auth/passkey/register/finish", {
        method: "POST",
        headers: { "X-WebAuthn-Session": begin.session_id || "" },
        body: JSON.stringify({ name: "browser", credential: body, ...body }),
      });
      setMsg($("passkeyMsg"), "Passkey 注册成功", true);
      loadPasskeys();
    } catch (e) { setMsg($("passkeyMsg"), e.message || String(e), false); }
  };

  async function loadSessions() {
    const data = await api("/api/v1/auth/sessions");
    const items = data.items || data || [];
    $("sessionList").innerHTML = items.length
      ? items.map((s) => `<div class="item"><div><strong>${s.device_id || "-"}</strong>
          <div class="meta">${s.ip || ""} · jti=${s.jti || ""} · ${s.created_at || s.updated_at || ""}</div></div>
          <button type="button" class="ghost" data-revoke="${s.jti}">撤销</button></div>`).join("")
      : `<div class="hint">暂无会话</div>`;
    $("sessionList").querySelectorAll("[data-revoke]").forEach((btn) => {
      btn.onclick = async () => {
        try {
          await api(`/api/v1/auth/sessions/${encodeURIComponent(btn.dataset.revoke)}`, { method: "DELETE" });
          loadSessions();
        } catch (e) { setMsg($("sessionMsg"), e.message, false); }
      };
    });
  }
  $("btnSessions").onclick = async () => {
    try { await loadSessions(); } catch (e) { setMsg($("sessionMsg"), e.message, false); }
  };
  $("btnRevokeOthers").onclick = async () => {
    try {
      await api("/api/v1/auth/sessions/revoke-others", { method: "POST", body: "{}" });
      setMsg($("sessionMsg"), "已退出其他设备", true);
      loadSessions();
    } catch (e) { setMsg($("sessionMsg"), e.message, false); }
  };

  async function loadNotify() {
    const data = await api("/api/v1/auth/notifications");
    const items = data.items || [];
    $("notifyList").innerHTML = items.length
      ? items.map((n) => `<div class="item"><div><strong>${n.title}</strong>
          <div class="meta">${n.created_at} · ${n.kind}${n.read ? " · 已读" : ""}</div>
          <div>${n.body || ""}</div></div>
          ${n.read ? "" : `<button type="button" class="ghost" data-read="${n.id}">标已读</button>`}</div>`).join("")
      : `<div class="hint">暂无通知</div>`;
    $("notifyList").querySelectorAll("[data-read]").forEach((btn) => {
      btn.onclick = async () => {
        await api(`/api/v1/auth/notifications/${btn.dataset.read}/read`, { method: "POST", body: "{}" });
        loadNotify();
      };
    });
  }
  $("btnNotify").onclick = async () => {
    try { await loadNotify(); } catch (e) { $("notifyList").textContent = e.message; }
  };

  if ($("token").value.trim()) {
    refreshMe().catch((e) => { $("outProfile").textContent = e.message; });
  } else if (forceMode) {
    $("forcePwd").classList.remove("hidden");
  }
})();
