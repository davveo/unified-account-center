(() => {
  const AUTH_KEY = "uac_admin_session";
  const TOKEN_KEY = "uac_admin_token"; // legacy
  const titles = {
    dashboard: ["运营概览", "登录成功率、OTP 发送量与刷短信告警"],
    apps: ["应用凭证", "创建 / 停用应用，查看 client_id / client_secret，轮换密钥"],
    tenants: ["租户管理", "租户列表 / 企业 SSO，页内 Tab 切换"],
    channels: ["对接渠道", "登录方式 / 短信通道 / JWT 签名钥"],
    users: ["用户管理", "用户列表 / 风控解锁"],
    invites: ["邀请 / 入驻", "邀请码 / 入驻审批 / 管理员建用户"],
    roles: ["角色权限", "轻量 RBAC：roles / scope 写入 JWT"],
    audits: ["审计日志", "查询与导出登录 / 绑定 / 密钥操作记录"],
    webhooks: ["Webhook", "出站事件订阅、签名校验与死信投递"],
    playground: ["渠道测试", "用真实接口联调验证码 / 密码 / OAuth 登录"],
  };

  const state = {
    channels: [],
    apps: [],
    appsForSelect: [],
    revealedSecrets: {},
    session: null,
  };

  const PAGE_SIZE = 10;
  const pages = {
    apps: 1,
    users: 1,
    audits: 1,
    tenants: 1,
    idps: 1,
    invites: 1,
    joins: 1,
    roles: 1,
  };

  const $ = (id) => document.getElementById(id);

  function pageParams(key) {
    const page = Math.max(1, pages[key] || 1);
    const limit = PAGE_SIZE;
    return { page, limit, offset: (page - 1) * limit };
  }

  function pagerHTML(key, total) {
    const n = Number(total) || 0;
    if (n <= 0) return "";
    const page = Math.max(1, pages[key] || 1);
    const totalPages = Math.max(1, Math.ceil(n / PAGE_SIZE));
    if (page > totalPages) pages[key] = totalPages;
    const cur = pages[key];
    const from = (cur - 1) * PAGE_SIZE + 1;
    const to = Math.min(cur * PAGE_SIZE, n);
    return `<div class="pager" data-pager-key="${key}" data-total="${n}">
      <div class="pager-info">显示 ${from}-${to} / 共 ${n} 条</div>
      <div class="pager-actions">
        <button type="button" class="btn btn-ghost btn-xs" data-pager-go="first" ${cur <= 1 ? "disabled" : ""}>首页</button>
        <button type="button" class="btn btn-ghost btn-xs" data-pager-go="prev" ${cur <= 1 ? "disabled" : ""}>上一页</button>
        <span class="pager-page">${cur} / ${totalPages}</span>
        <button type="button" class="btn btn-ghost btn-xs" data-pager-go="next" ${cur >= totalPages ? "disabled" : ""}>下一页</button>
        <button type="button" class="btn btn-ghost btn-xs" data-pager-go="last" ${cur >= totalPages ? "disabled" : ""}>末页</button>
      </div>
    </div>`;
  }

  function bindPager(container, key, reload) {
    const bar = container.querySelector(`[data-pager-key="${key}"]`);
    if (!bar) return;
    const total = Number(bar.dataset.total || 0);
    const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    bar.querySelectorAll("[data-pager-go]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const go = btn.dataset.pagerGo;
        if (go === "first") pages[key] = 1;
        else if (go === "prev") pages[key] = Math.max(1, (pages[key] || 1) - 1);
        else if (go === "next") pages[key] = Math.min(totalPages, (pages[key] || 1) + 1);
        else if (go === "last") pages[key] = totalPages;
        reload();
      });
    });
  }

  function withPager(bodyHTML, key, total, emptyHTML) {
    const n = Number(total) || 0;
    if (n <= 0) return emptyHTML || `<div class="text-sm text-mist">暂无数据</div>`;
    return `${bodyHTML}${pagerHTML(key, n)}`;
  }

  function loadSession() {
    try {
      const raw = localStorage.getItem(AUTH_KEY);
      if (raw) return JSON.parse(raw);
    } catch (_) {}
    const legacy = localStorage.getItem(TOKEN_KEY);
    if (legacy) {
      return { auth_type: "token", token: legacy, role: "platform_admin" };
    }
    return null;
  }

  function saveSession(sess) {
    state.session = sess;
    if (!sess) {
      localStorage.removeItem(AUTH_KEY);
      localStorage.removeItem(TOKEN_KEY);
      return;
    }
    localStorage.setItem(AUTH_KEY, JSON.stringify(sess));
    if (sess.auth_type === "token" && sess.token) {
      localStorage.setItem(TOKEN_KEY, sess.token);
    }
  }

  function authHeaders() {
    const headers = { "Content-Type": "application/json" };
    const sess = state.session || loadSession();
    if (!sess || !sess.token) return headers;
    if (sess.auth_type === "bearer") {
      headers.Authorization = `Bearer ${sess.token}`;
    } else {
      headers["X-Admin-Token"] = sess.token;
    }
    return headers;
  }

  function setOutput(obj) {
    $("testOutput").textContent = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
  }

  function escapeHtml(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  /* ===================== Toast / Modal ===================== */
  let modalResolver = null;
  let modalCollector = null;

  function toast(message, type = "ok") {
    const root = $("toastRoot");
    const el = document.createElement("div");
    el.className = `toast ${type}`;
    el.innerHTML = `<span class="toast-dot"></span><div class="toast-text">${escapeHtml(message)}</div>`;
    root.appendChild(el);
    setTimeout(() => {
      el.style.opacity = "0";
      el.style.transform = "translateY(6px)";
      el.style.transition = "opacity .18s ease, transform .18s ease";
      setTimeout(() => el.remove(), 200);
    }, 2800);
  }

  function closeModal(result) {
    const root = $("modalRoot");
    root.classList.add("hidden");
    root.setAttribute("aria-hidden", "true");
    $("modalBody").innerHTML = "";
    $("modalFoot").innerHTML = "";
    document.removeEventListener("keydown", onModalKeydown);
    const resolve = modalResolver;
    modalResolver = null;
    modalCollector = null;
    if (resolve) resolve(result);
  }

  function onModalKeydown(e) {
    if (e.key === "Escape") closeModal(null);
  }

  function openModal({ title, bodyHTML, wide, primaryText = "确定", secondaryText = "取消", danger, hideCancel, collect }) {
    return new Promise((resolve) => {
      if (modalResolver) closeModal(null);
      modalResolver = resolve;
      modalCollector = typeof collect === "function" ? collect : null;

      const root = $("modalRoot");
      const panel = root.querySelector(".modal-panel");
      panel.classList.toggle("modal-wide", !!wide);
      $("modalTitle").textContent = title || "提示";
      $("modalBody").innerHTML = bodyHTML || "";

      const foot = $("modalFoot");
      foot.innerHTML = "";
      if (!hideCancel) {
        const cancel = document.createElement("button");
        cancel.type = "button";
        cancel.className = "btn btn-ghost";
        cancel.textContent = secondaryText;
        cancel.addEventListener("click", () => closeModal(null));
        foot.appendChild(cancel);
      }

      const ok = document.createElement("button");
      ok.type = "button";
      ok.className = "btn btn-primary";
      if (danger) {
        ok.style.background = "#b91c1c";
        ok.style.borderColor = "#b91c1c";
      }
      ok.textContent = primaryText;
      ok.addEventListener("click", () => {
        if (modalCollector) {
          const values = modalCollector($("modalBody"));
          if (values === false) return;
          closeModal(values);
          return;
        }
        closeModal(true);
      });
      foot.appendChild(ok);

      root.querySelectorAll("[data-modal-dismiss]").forEach((el) => {
        el.onclick = () => closeModal(null);
      });

      root.classList.remove("hidden");
      root.setAttribute("aria-hidden", "false");
      document.addEventListener("keydown", onModalKeydown);

      const firstInput = $("modalBody").querySelector("input, textarea, select");
      if (firstInput) {
        setTimeout(() => {
          firstInput.focus();
          if (firstInput.select) firstInput.select();
        }, 20);
        firstInput.addEventListener("keydown", (e) => {
          if (e.key === "Enter" && firstInput.tagName !== "TEXTAREA") {
            e.preventDefault();
            ok.click();
          }
        });
      } else {
        ok.focus();
      }
    });
  }

  function uiAlert(message, { title = "提示", mono = false } = {}) {
    return openModal({
      title,
      bodyHTML: `<div class="modal-msg${mono ? " mono" : ""}">${escapeHtml(message)}</div>`,
      primaryText: "知道了",
      hideCancel: true,
    });
  }

  function uiConfirm(message, { title = "请确认", danger = false, primaryText = "确认" } = {}) {
    return openModal({
      title,
      bodyHTML: `<div class="modal-msg">${escapeHtml(message)}</div>`,
      primaryText,
      danger,
    }).then((v) => !!v);
  }

  function uiPrompt(message, { title = "请输入", defaultValue = "", placeholder = "", required = true } = {}) {
    return openModal({
      title,
      bodyHTML: `
        <div class="modal-fields">
          <label class="field-label" for="modalPromptInput">${escapeHtml(message)}</label>
          <input id="modalPromptInput" class="input" value="${escapeHtml(defaultValue)}" placeholder="${escapeHtml(placeholder)}" />
        </div>`,
      collect(body) {
        const input = body.querySelector("#modalPromptInput");
        const val = input.value.trim();
        if (required && !val) {
          input.focus();
          return false;
        }
        return val;
      },
    });
  }

  function uiForm(title, fields, { wide, primaryText = "确定" } = {}) {
    const bodyHTML = `<div class="modal-fields">${fields.map((f, i) => {
      const id = `modalField_${i}`;
      if (f.type === "checkbox") {
        return `<label class="modal-check"><input id="${id}" type="checkbox" ${f.checked ? "checked" : ""}/> ${escapeHtml(f.label)}</label>`;
      }
      if (f.type === "select") {
        const opts = (f.options || []).map((o) => `<option value="${escapeHtml(o.value)}" ${o.value === f.value ? "selected" : ""}>${escapeHtml(o.label || o.value)}</option>`).join("");
        return `<div><label class="field-label" for="${id}">${escapeHtml(f.label)}</label><select id="${id}" class="input">${opts}</select></div>`;
      }
      if (f.type === "textarea") {
        return `<div>
          <label class="field-label" for="${id}">${escapeHtml(f.label)}</label>
          <textarea id="${id}" class="input min-h-[84px]" rows="4" placeholder="${escapeHtml(f.placeholder || "")}">${escapeHtml(f.value || "")}</textarea>
          ${f.hint ? `<p class="modal-hint">${escapeHtml(f.hint)}</p>` : ""}
        </div>`;
      }
      return `<div>
        <label class="field-label" for="${id}">${escapeHtml(f.label)}</label>
        <input id="${id}" class="input" type="${f.type || "text"}" value="${escapeHtml(f.value || "")}" placeholder="${escapeHtml(f.placeholder || "")}" />
        ${f.hint ? `<p class="modal-hint">${escapeHtml(f.hint)}</p>` : ""}
      </div>`;
    }).join("")}</div>`;

    return openModal({
      title,
      bodyHTML,
      wide,
      primaryText,
      collect(body) {
        const out = {};
        for (let i = 0; i < fields.length; i++) {
          const f = fields[i];
          const el = body.querySelector(`#modalField_${i}`);
          if (f.type === "checkbox") {
            out[f.name] = el.checked;
            continue;
          }
          const val = el.value.trim();
          if (f.required && !val) {
            el.focus();
            return false;
          }
          out[f.name] = val;
        }
        return out;
      },
    });
  }

  /* ===================== API ===================== */
  class AuthError extends Error {
    constructor(message) {
      super(message);
      this.name = "AuthError";
    }
  }

  async function api(path, options = {}) {
    if (!state.session || !state.session.token) {
      showLogin("请先登录管理后台");
      throw new AuthError("未登录");
    }
    const headers = Object.assign(authHeaders(), options.headers || {});
    const res = await fetch(path, { ...options, headers });
    const body = await res.json().catch(() => ({}));
    if (res.status === 401 || body.code === 40100) {
      showLogin(body.message || "登录已失效，请重新登录");
      throw new AuthError(body.message || "未登录");
    }
    if (!res.ok || body.code !== 0) {
      throw new Error(body.message || res.statusText || "请求失败");
    }
    return body.data;
  }

  async function authAPI(path, { method = "GET", body, clientId, clientSecret } = {}) {
    const headers = { "Content-Type": "application/json", "X-Client-Id": clientId };
    if (clientSecret) headers["X-Client-Secret"] = clientSecret;
    const res = await fetch(path, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
    return res.json().catch(() => ({}));
  }

  function showLogin(errMsg) {
    saveSession(null);
    $("loginGate").classList.remove("hidden");
    $("appShell").classList.add("hidden");
    const err = $("loginError");
    if (errMsg) {
      err.textContent = errMsg;
      err.classList.remove("hidden");
    } else {
      err.classList.add("hidden");
      err.textContent = "";
    }
  }

  function showApp(session) {
    saveSession(session);
    $("loginGate").classList.add("hidden");
    $("appShell").classList.remove("hidden");
    $("loginError").classList.add("hidden");
    renderSessionBar(session);
  }

  function renderSessionBar(session) {
    if (!session) {
      $("sessionLabel").textContent = "未登录";
      $("sessionMeta").textContent = "";
      return;
    }
    if (session.auth_type === "bearer") {
      $("sessionLabel").textContent = session.display_name || session.user_id || "管理员账号";
      $("sessionMeta").textContent = `${session.role || ""}${session.tenant_id ? " · " + session.tenant_id : ""}`;
    } else {
      $("sessionLabel").textContent = "平台超管 Token";
      $("sessionMeta").textContent = session.role || "platform_admin";
    }
  }

  async function enterConsole(session) {
    showApp(session);
    await loadChannels();
    renderMethodChecks();
    switchView("dashboard");
  }

  async function loadDashboard() {
    try {
      const tenant = ($("dashTenant")?.value || "default").trim() || "default";
      const d = await api(`/api/v1/admin/dashboard?tenant_id=${encodeURIComponent(tenant)}`);
      const p = d.process || {};
      const a = d.audit_24h || {};
      const pct = ((p.login_success_rate || 0) * 100).toFixed(1);
      const pct24 = ((a.login_success_rate || 0) * 100).toFixed(1);
      const tid = d.tenant_id || tenant;
      $("dashCards").innerHTML = [
        ["登录成功率(进程)", pct + "%", `${p.login_ok || 0} / ${(p.login_ok || 0) + (p.login_fail || 0)}`],
        ["OTP 发送量", String(p.otp_sent || 0), "进程累计"],
        ["刷短信告警", String(p.otp_limit_hits || 0), "日限额命中"],
        ["短信通道", d.sms_provider || "-", "热更新可用"],
        ["应用配额", `${(d.quota && d.quota.apps_used) || 0}/${(d.quota && d.quota.apps_max) || "-"}`, `租户 ${tid}`],
        ["今日发码", `${(d.quota && d.quota.otp_today) || 0}/${(d.quota && d.quota.otp_daily_limit) || "-"}`, `租户 ${tid}`],
      ].map(([t, v, s]) => `
        <article class="panel">
          <div class="text-xs font-medium uppercase tracking-wide text-mist">${escapeHtml(t)}</div>
          <div class="mt-2 text-3xl font-semibold tracking-tight">${escapeHtml(v)}</div>
          <div class="mt-1 text-xs text-mist">${escapeHtml(s)}</div>
        </article>`).join("");
      $("dashAudit").innerHTML = `
        <div class="grid grid-cols-2 gap-3">
          <div><div class="text-mist text-xs">成功登录</div><div class="text-xl font-semibold">${a.login_ok || 0}</div></div>
          <div><div class="text-mist text-xs">失败登录</div><div class="text-xl font-semibold">${a.login_fail || 0}</div></div>
          <div><div class="text-mist text-xs">发码成功</div><div class="text-xl font-semibold">${a.challenge || 0}</div></div>
          <div><div class="text-mist text-xs">成功率</div><div class="text-xl font-semibold">${pct24}%</div></div>
        </div>
        <div class="mt-3 text-xs text-mist">租户 ${escapeHtml(tid)} · 生成于 ${escapeHtml(d.generated_at || "")}</div>`;
      const alerts = d.sms_alerts || [];
      const moreBtn = `<div class="mt-3 flex items-center justify-between gap-2">
        <div class="text-xs text-mist">仅展示近 24h 最近 20 条</div>
        <button type="button" class="btn btn-ghost btn-xs" id="btnMoreOTPAlerts">查看更多</button>
      </div>`;
      $("dashAlerts").innerHTML = (alerts.length
        ? `<div class="overflow-x-auto"><table class="table-base"><thead><tr><th>时间</th><th>action</th><th>detail</th></tr></thead>
           <tbody>${alerts.map((x) => `<tr>
             <td class="text-xs whitespace-nowrap">${escapeHtml(x.created_at)}</td>
             <td class="font-mono text-xs">${escapeHtml(x.action)}</td>
             <td class="text-xs text-mist">${escapeHtml(x.detail)}</td>
           </tr>`).join("")}</tbody></table></div>`
        : `<div class="text-sm text-mist">近 24h 暂无 OTP 相关告警</div>`) + moreBtn;
      $("btnMoreOTPAlerts")?.addEventListener("click", () => {
        const from = new Date();
        from.setDate(from.getDate() - 1);
        const yyyy = from.getFullYear();
        const mm = String(from.getMonth() + 1).padStart(2, "0");
        const dd = String(from.getDate()).padStart(2, "0");
        if ($("auditAction")) $("auditAction").value = "otp_limit_alert";
        if ($("auditUser")) $("auditUser").value = "";
        if ($("auditFrom")) $("auditFrom").value = `${yyyy}-${mm}-${dd}`;
        if ($("auditTo")) $("auditTo").value = "";
        pages.audits = 1;
        switchView("audits");
      });
    } catch (e) {
      $("dashCards").innerHTML = `<div class="result warn">${escapeHtml(e.message)}</div>`;
    }
  }

  async function fillDashTenants() {
    const sel = $("dashTenant");
    if (!sel) return;
    try {
      const data = await api("/api/v1/admin/tenants?limit=200&offset=0");
      const items = data.items || [];
      const cur = sel.value || "default";
      sel.innerHTML = items.length
        ? items.map((t) => `<option value="${escapeHtml(t.tenant_id)}">${escapeHtml(t.name || t.tenant_id)}</option>`).join("")
        : `<option value="default">default</option>`;
      sel.value = items.some((t) => t.tenant_id === cur) ? cur : (items[0]?.tenant_id || "default");
    } catch (_) { /* keep default */ }
  }

  async function loadSMSChannel() {
    try {
      const d = await api("/api/v1/admin/sms-channel");
      $("smsChannelBox").innerHTML = `
        <div class="text-sm">当前 provider：<span class="font-mono font-semibold">${escapeHtml(d.provider)}</span>
          ${d.mq_enabled ? "" : "（MQ 未启用，仅 mock 可用）"}</div>
        <div class="flex flex-wrap gap-2">
          <button type="button" class="btn btn-primary" data-sms="mock">切换 mock</button>
          <button type="button" class="btn btn-ghost" data-sms="mq" ${d.mq_enabled ? "" : "disabled"}>切换 mq</button>
        </div>
        <div class="text-xs text-mist">topic=${escapeHtml(d.mq_topic || "-")} · updated=${escapeHtml(d.updated_at || "-")}</div>`;
      $("smsChannelBox").querySelectorAll("[data-sms]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          try {
            await api("/api/v1/admin/sms-channel", {
              method: "PUT",
              body: JSON.stringify({ provider: btn.dataset.sms }),
            });
            toast("短信通道已热更新");
            loadSMSChannel();
            loadDashboard();
          } catch (e) { uiAlert(e.message); }
        });
      });
    } catch (e) {
      $("smsChannelBox").innerHTML = `<div class="result warn">${escapeHtml(e.message)}</div>`;
    }
  }

  async function loadJWTKeys() {
    try {
      const d = await api("/api/v1/admin/jwt-keys");
      const dual = d.dual_key
        ? `<span class="badge badge-ok">双钥生效</span>`
        : `<span class="badge badge-warn">仅当前钥</span>`;
      $("jwtKeysBox").innerHTML = `
        <div class="text-sm space-y-1">
          <div>算法：<span class="font-mono font-semibold">${escapeHtml(d.alg || "-")}</span> ${dual}</div>
          <div>当前 kid（签名）：<span class="font-mono font-semibold">${escapeHtml(d.current_kid || "-")}</span></div>
          <div>旧 kid（只验）：<span class="font-mono">${escapeHtml(d.previous_kid || "无")}</span></div>
          <div class="text-xs text-mist">${escapeHtml(d.note || "")}</div>
          <div class="text-xs text-mist font-mono break-all">curr=${escapeHtml(d.private_key_path || "-")} · prev=${escapeHtml(d.previous_private_key_path || "-")}</div>
        </div>
        <div class="flex flex-wrap gap-2">
          <button type="button" class="btn btn-primary" data-jwt="rotate">轮换签名钥</button>
          <button type="button" class="btn btn-ghost" data-jwt="retire" ${d.previous_kid ? "" : "disabled"}>下线旧钥</button>
        </div>`;
      $("jwtKeysBox").querySelectorAll("[data-jwt]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          try {
            if (btn.dataset.jwt === "rotate") {
              const ok = await uiConfirm("确认轮换 JWT 签名钥？新 token 将使用新 kid；旧 token 在过期前仍可验签。", {
                title: "轮换 JWT 签名钥",
              });
              if (!ok) return;
              const data = await api("/api/v1/admin/jwt-keys/rotate", { method: "POST", body: "{}" });
              toast(`已轮换：${data.current_kid}`);
            } else {
              const ok = await uiConfirm("确认下线旧钥？带旧 kid 的 Access Token 将立即验签失败。", {
                title: "下线旧钥",
              });
              if (!ok) return;
              await api("/api/v1/admin/jwt-keys/retire-previous", { method: "POST", body: "{}" });
              toast("旧钥已下线");
            }
            loadJWTKeys();
          } catch (e) { uiAlert(e.message); }
        });
      });
    } catch (e) {
      $("jwtKeysBox").innerHTML = `<div class="result warn">${escapeHtml(e.message)}</div>`;
    }
  }

  function auditQuery() {
    const user = encodeURIComponent(($("auditUser")?.value || "").trim());
    const action = encodeURIComponent(($("auditAction")?.value || "").trim());
    const requestId = encodeURIComponent(($("auditRequestId")?.value || "").trim());
    const jti = encodeURIComponent(($("auditJti")?.value || "").trim());
    const deviceId = encodeURIComponent(($("auditDeviceId")?.value || "").trim());
    const from = encodeURIComponent(($("auditFrom")?.value || "").trim());
    const to = encodeURIComponent(($("auditTo")?.value || "").trim());
    return `user_id=${user}&action=${action}&request_id=${requestId}&jti=${jti}&device_id=${deviceId}&from=${from}&to=${to}`;
  }

  async function loadWebhooks() {
    try {
      const d = await api("/api/v1/admin/webhooks");
      const items = d.items || [];
      $("webhooksTable").innerHTML = items.length
        ? `<table class="table"><thead><tr><th>名称</th><th>URL</th><th>事件</th><th>状态</th><th></th></tr></thead><tbody>
          ${items.map((w) => `<tr>
            <td>${escapeHtml(w.name)}</td>
            <td class="font-mono text-xs">${escapeHtml(w.url)}</td>
            <td class="text-xs">${escapeHtml((w.events || []).join(",") || "*")}</td>
            <td>${w.enabled ? "启用" : "停用"}</td>
            <td><button type="button" class="btn btn-ghost btn-xs" data-del-wh="${w.id}">删除</button></td>
          </tr>`).join("")}
        </tbody></table>`
        : `<div class="text-sm text-mist">暂无订阅</div>`;
      $("webhooksTable").querySelectorAll("[data-del-wh]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          if (!(await uiConfirm("删除该 Webhook？"))) return;
          await api(`/api/v1/admin/webhooks/${btn.dataset.delWh}`, { method: "DELETE" });
          toast("已删除");
          loadWebhooks();
        });
      });
      const del = await api("/api/v1/admin/webhooks/deliveries?limit=20");
      const rows = del.items || [];
      $("webhookDeliveries").innerHTML = rows.length
        ? `<table class="table"><thead><tr><th>事件</th><th>状态</th><th>尝试</th><th>HTTP</th><th>错误</th></tr></thead><tbody>
          ${rows.map((r) => `<tr>
            <td class="font-mono text-xs">${escapeHtml(r.event_type)}</td>
            <td>${escapeHtml(r.status)}</td>
            <td>${r.attempts}</td>
            <td>${r.last_http_status || "-"}</td>
            <td class="text-xs">${escapeHtml(r.last_error || "")}</td>
          </tr>`).join("")}
        </tbody></table>`
        : `<div class="text-sm text-mist">暂无投递</div>`;
    } catch (e) {
      $("webhooksTable").innerHTML = `<div class="result warn">${escapeHtml(e.message)}</div>`;
    }
  }

  async function exportAudits(persist) {
    try {
      const qs = auditQuery() + (persist ? "&persist=1" : "");
      if (persist) {
        const data = await api(`/api/v1/admin/audits/export?${qs}`);
        await uiAlert(`已写入对象存储\n文件：${data.filename}\n路径：${data.path}\n下载：${data.url}`, { mono: true, title: "导出成功" });
        return;
      }
      const headers = authHeaders();
      const res = await fetch(`/api/v1/admin/audits/export?${qs}`, { headers });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.message || "导出失败");
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `audits_${Date.now()}.csv`;
      a.click();
      URL.revokeObjectURL(url);
      toast("CSV 已下载");
    } catch (e) { uiAlert(e.message); }
  }

  async function restoreSession() {
    const sess = loadSession();
    if (!sess || !sess.token) {
      showLogin();
      return;
    }
    state.session = sess;
    try {
      const me = await api("/api/v1/admin/me");
      await enterConsole({
        ...sess,
        role: me.role || sess.role,
        roles: me.roles || sess.roles,
        user_id: me.user_id || sess.user_id,
        tenant_id: me.tenant_id || sess.tenant_id,
        display_name: me.display_name || sess.display_name,
        auth_type: me.auth_type || sess.auth_type,
      });
    } catch (e) {
      if (!(e instanceof AuthError)) {
        showLogin(e.message || "会话校验失败");
      }
    }
  }

  function activateSubTab(viewEl, tabId, { load = true } = {}) {
    if (!viewEl || !tabId) return;
    viewEl.querySelectorAll(".subtab").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.subtab === tabId);
    });
    viewEl.querySelectorAll(".subpanel").forEach((panel) => {
      panel.classList.toggle("active", panel.dataset.subpanel === tabId);
    });
    if (!load) return;
    switch (tabId) {
      case "tenants-list":
        loadTenants();
        break;
      case "tenants-idp":
        loadIdPs();
        break;
      case "channels-list":
        loadChannels();
        break;
      case "channels-sms":
        loadSMSChannel();
        break;
      case "channels-jwt":
        loadJWTKeys();
        break;
      case "users-list":
        loadUsers();
        break;
      case "users-risk":
        break;
      case "invites-codes":
        loadInvites();
        break;
      case "invites-joins":
        loadJoins();
        break;
      case "invites-create":
        break;
      default:
        break;
    }
  }

  function switchView(name) {
    document.querySelectorAll(".nav-item").forEach((el) => {
      el.classList.toggle("active", el.dataset.view === name);
    });
    document.querySelectorAll(".view").forEach((el) => {
      el.classList.toggle("active", el.id === `view-${name}`);
    });
    $("pageTitle").textContent = titles[name][0];
    $("pageDesc").textContent = titles[name][1];

    const viewEl = $(`view-${name}`);
    if (viewEl && viewEl.hasAttribute("data-subtabs")) {
      const active = viewEl.querySelector(".subtab.active") || viewEl.querySelector(".subtab");
      if (active) activateSubTab(viewEl, active.dataset.subtab, { load: true });
      return;
    }

    if (name === "dashboard") {
      fillDashTenants().finally(() => loadDashboard());
    }
    if (name === "playground") preparePlayground();
    if (name === "apps") loadApps();
    if (name === "audits") loadAudits();
    if (name === "webhooks") loadWebhooks();
    if (name === "roles") loadRoles();
  }

  function renderMethodChecks(selected) {
    const defaults = ["phone_otp", "phone_password", "email_otp", "email_password"];
    const methods = state.channels.length ? state.channels.map((c) => c.method) : defaults;
    $("methodChecks").innerHTML = methods
      .map((m) => {
        const checked = (selected || defaults).includes(m) ? "checked" : "";
        return `<label class="check-item"><input type="checkbox" name="methods" value="${m}" ${checked}/> <span class="font-mono text-xs">${m}</span></label>`;
      })
      .join("");
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_) {
      return false;
    }
  }

  function statusBadge(status) {
    if (status === "active") return `<span class="badge badge-ok">active</span>`;
    return `<span class="badge badge-warn">${escapeHtml(status || "-")}</span>`;
  }

  async function loadChannels() {
    try {
      const data = await api("/api/v1/admin/channels");
      state.channels = data.channels || [];
      renderMethodChecks();
      let oauthHTML = "";
      try {
        const providers = await api("/api/v1/admin/oauth-providers");
        const items = providers.items || [];
        oauthHTML = `<div class="channel-card sm:col-span-2 xl:col-span-3">
          <h3 class="text-base font-semibold">OAuth Provider（可热更新）</h3>
          <p class="mt-1 text-sm text-mist">PUT /api/v1/admin/oauth-providers 写入后立即生效，无需发版。</p>
          <div class="mt-2 font-mono text-xs leading-relaxed">${items.map((p) => `${escapeHtml(p.name)} [${escapeHtml(p.kind || "generic")}] client_id=${escapeHtml(p.client_id || "-")} enabled=${p.enabled}`).join("<br/>") || "暂无"}</div>
          <button id="upsertOAuthBtn" type="button" class="btn btn-ghost mt-3">新增/更新 Provider</button>
        </div>`;
      } catch (_) {}
      $("channelsGrid").innerHTML = state.channels
        .map((ch) => {
          const status = ch.method === "oauth2"
            ? (ch.configured
              ? `<span class="badge badge-ok">已配置 Provider</span>`
              : `<span class="badge badge-warn">未配置 OAuth 密钥</span>`)
            : `<span class="badge badge-ok">可用</span>`;
          const providers = (ch.providers || []).length
            ? `<div class="mt-2 font-mono text-xs text-mist">${ch.providers.map(escapeHtml).join(", ")}</div>`
            : "";
          return `<div class="channel-card">
            <h3 class="text-base font-semibold">${escapeHtml(ch.name)}</h3>
            <div class="mt-2 flex flex-wrap gap-1.5">${status}<span class="badge badge-muted">${escapeHtml(ch.category)}</span></div>
            <p class="mt-2 text-sm text-mist">${escapeHtml(ch.description)}</p>
            <div class="mt-2 font-mono text-xs">${escapeHtml(ch.method)}</div>
            ${providers}
          </div>`;
        })
        .join("") + oauthHTML;

      const btn = $("upsertOAuthBtn");
      if (btn) {
        btn.onclick = async () => {
          const values = await uiForm("新增 / 更新 OAuth Provider", [
            { name: "name", label: "Provider 名称", value: "wechat", placeholder: "wechat / github", required: true },
            {
              name: "kind", label: "类型", type: "select", value: "wechat",
              options: [
                { value: "generic", label: "generic" },
                { value: "wechat", label: "wechat" },
                { value: "wecom", label: "wecom" },
                { value: "google", label: "google" },
                { value: "apple", label: "apple" },
                { value: "dingtalk", label: "dingtalk" },
                { value: "feishu", label: "feishu" },
              ],
            },
            { name: "client_id", label: "client_id / appid / corpid", placeholder: "必填", required: true },
            { name: "client_secret", label: "client_secret", placeholder: "可空表示不改", hint: "留空则保留原有 secret" },
          ]);
          if (!values) return;
          try {
            await api("/api/v1/admin/oauth-providers", {
              method: "PUT",
              body: JSON.stringify({
                name: values.name,
                kind: values.kind,
                client_id: values.client_id,
                client_secret: values.client_secret,
                enabled: true,
              }),
            });
            toast("Provider 已保存");
            loadChannels();
          } catch (e) {
            uiAlert(e.message, { title: "保存失败" });
          }
        };
      }
    } catch (e) {
      $("channelsGrid").innerHTML = `<div class="result warn">${escapeHtml(e.message)}</div>`;
    }
  }

  function renderAppCard(a) {
    const id = escapeHtml(a.client_id);
    const revealed = state.revealedSecrets[a.client_id];
    const secretText = revealed || a.secret_masked || "••••••••••••••••";
    const revealLabel = revealed ? "隐藏" : "查看";
    const methods = (a.allowed_methods || []).map((m) => `<span class="badge badge-muted">${escapeHtml(m)}</span>`).join(" ");
    return `<article class="rounded-xl border border-line bg-white p-4">
      <div class="flex flex-wrap items-start justify-between gap-3">
        <div class="min-w-0">
          <div class="flex flex-wrap items-center gap-2">
            <h3 class="text-base font-semibold">${escapeHtml(a.name)}</h3>
            ${statusBadge(a.status)}
          </div>
          <div class="mt-2 flex flex-wrap gap-1.5">${methods || `<span class="text-xs text-mist">未配置登录方式</span>`}</div>
        </div>
        <div class="action-row">
          <button type="button" class="btn btn-ghost btn-xs" data-act="toggle" data-id="${id}" data-status="${escapeHtml(a.status)}">${a.status === "active" ? "停用" : "启用"}</button>
          <button type="button" class="btn btn-ghost btn-xs" data-act="methods" data-id="${id}">改方式</button>
          <button type="button" class="btn btn-ghost btn-xs" data-act="urls" data-id="${id}">回调/CORS</button>
          <button type="button" class="btn btn-ghost btn-xs" data-act="brand" data-id="${id}">主题</button>
          <button type="button" class="btn btn-ghost btn-xs" data-act="rotate" data-id="${id}">轮换密钥</button>
          <a class="btn btn-ghost btn-xs" href="/login?client_id=${encodeURIComponent(a.client_id)}&redirect_uri=${encodeURIComponent((a.redirect_uris || [])[0] || "")}" target="_blank" rel="noopener">托管登录</a>
        </div>
      </div>
      <div class="cred-box mt-4">
        <div class="cred-row">
          <span class="cred-label">client_id</span>
          <code class="cred-value">${id}</code>
          <button type="button" class="btn btn-ghost btn-xs" data-copy="${id}">复制</button>
        </div>
        <div class="cred-row">
          <span class="cred-label">client_secret</span>
          <code class="cred-value" data-secret-value="${id}">${escapeHtml(secretText)}</code>
          <button type="button" class="btn btn-ghost btn-xs" data-reveal="${id}" data-has="${a.has_secret ? "1" : "0"}">${revealLabel}</button>
          <button type="button" class="btn btn-ghost btn-xs" data-copy-secret="${id}" ${revealed ? "" : "disabled"}>复制</button>
        </div>
      </div>
    </article>`;
  }

  async function loadApps({ reset } = {}) {
    if (reset) pages.apps = 1;
    try {
      const { limit, offset } = pageParams("apps");
      const data = await api(`/api/v1/admin/apps?limit=${limit}&offset=${offset}`);
      state.apps = data.items || [];
      const total = data.total || state.apps.length;
      if (!state.apps.length && total === 0) {
        $("appsTable").innerHTML = `<div class="text-sm text-mist">暂无应用，请先创建。</div>`;
        return;
      }
      if (!state.apps.length && total > 0) {
        pages.apps = Math.max(1, Math.ceil(total / PAGE_SIZE));
        return loadApps();
      }
      $("appsTable").innerHTML = withPager(
        `<div class="grid gap-3">${state.apps.map(renderAppCard).join("")}</div>`,
        "apps",
        total
      );
      bindAppCardEvents();
      bindPager($("appsTable"), "apps", () => loadApps());
    } catch (e) {
      $("appsTable").innerHTML = `<div class="result warn">${escapeHtml(e.message)}</div>`;
    }
  }

  async function loadAppsForSelect() {
    try {
      const data = await api("/api/v1/admin/apps?limit=200&offset=0");
      state.appsForSelect = data.items || [];
      fillClientSelect();
    } catch (_) {
      /* ignore */
    }
  }

  function bindAppCardEvents() {
    $("appsTable").querySelectorAll("button[data-act]").forEach((btn) => {
      btn.addEventListener("click", () => onAppAction(btn.dataset.act, btn.dataset.id, btn.dataset.status));
    });
    $("appsTable").querySelectorAll("button[data-copy]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const ok = await copyText(btn.dataset.copy);
        toast(ok ? "client_id 已复制" : "复制失败", ok ? "ok" : "err");
      });
    });
    $("appsTable").querySelectorAll("button[data-copy-secret]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const plain = state.revealedSecrets[btn.dataset.copySecret];
        if (!plain) return;
        const ok = await copyText(plain);
        toast(ok ? "client_secret 已复制" : "复制失败", ok ? "ok" : "err");
      });
    });
    $("appsTable").querySelectorAll("button[data-reveal]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const clientId = btn.dataset.reveal;
        const valueEl = $("appsTable").querySelector(`[data-secret-value="${CSS.escape(clientId)}"]`);
        const copyBtn = $("appsTable").querySelector(`[data-copy-secret="${CSS.escape(clientId)}"]`);
        if (state.revealedSecrets[clientId]) {
          delete state.revealedSecrets[clientId];
          const app = state.apps.find((x) => x.client_id === clientId);
          if (valueEl) valueEl.textContent = (app && app.secret_masked) || "••••••••••••••••";
          btn.textContent = "查看";
          if (copyBtn) copyBtn.disabled = true;
          return;
        }
        if (btn.dataset.has !== "1") {
          uiAlert("该应用密钥仅存哈希，请先「轮换密钥」后再查看。", { title: "无法查看" });
          return;
        }
        try {
          btn.disabled = true;
          btn.textContent = "加载中…";
          const data = await api(`/api/v1/admin/apps/${encodeURIComponent(clientId)}/secret`);
          state.revealedSecrets[clientId] = data.client_secret;
          if (valueEl) valueEl.textContent = data.client_secret;
          btn.textContent = "隐藏";
          if (copyBtn) copyBtn.disabled = false;
        } catch (e) {
          uiAlert(e.message, { title: "查看失败" });
          btn.textContent = "查看";
        } finally {
          btn.disabled = false;
        }
      });
    });
  }

  async function onAppAction(act, clientId, status) {
    try {
      if (act === "toggle") {
        const next = status === "active" ? "disabled" : "active";
        const ok = await uiConfirm(
          next === "disabled" ? `确认停用应用 ${clientId}？` : `确认启用应用 ${clientId}？`,
          { title: "变更状态", danger: next === "disabled" }
        );
        if (!ok) return;
        await api(`/api/v1/admin/apps/${encodeURIComponent(clientId)}`, {
          method: "PATCH",
          body: JSON.stringify({ status: next }),
        });
        toast(next === "disabled" ? "应用已停用" : "应用已启用");
        loadApps();
      } else if (act === "methods") {
        const current = (state.apps.find((a) => a.client_id === clientId)?.allowed_methods || []).join(",");
        const raw = await uiPrompt("输入 allowed_methods，逗号分隔", {
          title: "修改登录方式",
          defaultValue: current || "phone_otp,email_otp,phone_password,email_password",
        });
        if (!raw) return;
        await api(`/api/v1/admin/apps/${encodeURIComponent(clientId)}`, {
          method: "PATCH",
          body: JSON.stringify({ allowed_methods: raw.split(",").map((s) => s.trim()).filter(Boolean) }),
        });
        toast("登录方式已更新");
        loadApps();
      } else if (act === "urls") {
        const app = state.apps.find((a) => a.client_id === clientId) || {};
        const values = await uiForm("回调域名 / CORS", [
          { name: "redirect_uris", label: "Redirect URIs（每行一个）", type: "textarea", value: (app.redirect_uris || []).join("\n"), required: false },
          { name: "cors_origins", label: "CORS Origins（每行一个）", type: "textarea", value: (app.cors_origins || []).join("\n"), required: false },
        ]);
        if (!values) return;
        const redirects = String(values.redirect_uris || "").split("\n").map((s) => s.trim()).filter(Boolean);
        const cors = String(values.cors_origins || "").split("\n").map((s) => s.trim()).filter(Boolean);
        await api(`/api/v1/admin/apps/${encodeURIComponent(clientId)}`, {
          method: "PATCH",
          body: JSON.stringify({ redirect_uris: redirects, cors_origins: cors }),
        });
        toast("回调域名 / CORS 已更新");
        loadApps();
      } else if (act === "brand") {
        const app = state.apps.find((a) => a.client_id === clientId) || {};
        const values = await uiForm("托管登录主题", [
          { name: "login_title", label: "登录页标题", value: app.login_title || "欢迎登录", required: true },
          { name: "logo_url", label: "Logo URL", value: app.logo_url || "", placeholder: "可空" },
          { name: "theme_color", label: "主题色", value: app.theme_color || "#0f766e", placeholder: "#0f766e" },
          { name: "require_pkce", label: "强制 PKCE", type: "checkbox", checked: !!app.require_pkce },
        ]);
        if (!values) return;
        await api(`/api/v1/admin/apps/${encodeURIComponent(clientId)}`, {
          method: "PATCH",
          body: JSON.stringify({
            login_title: values.login_title,
            logo_url: values.logo_url,
            theme_color: values.theme_color,
            require_pkce: values.require_pkce,
          }),
        });
        toast("主题已保存");
        loadApps();
      } else if (act === "rotate") {
        const ok = await uiConfirm("确认轮换密钥？旧 secret 将立即失效。", {
          title: "轮换密钥",
          danger: true,
          primaryText: "确认轮换",
        });
        if (!ok) return;
        const data = await api(`/api/v1/admin/apps/${encodeURIComponent(clientId)}/rotate-secret`, {
          method: "POST",
          body: "{}",
        });
        state.revealedSecrets[clientId] = data.client_secret;
        await uiAlert(`新 client_secret 已生成，可在列表中查看/复制：\n\n${data.client_secret}`, {
          title: "轮换成功",
          mono: true,
        });
        loadApps();
      }
    } catch (e) {
      uiAlert(e.message, { title: "操作失败" });
    }
  }

  async function loadUsers({ reset } = {}) {
    if (reset) pages.users = 1;
    try {
      const q = encodeURIComponent($("userQuery").value.trim());
      const { limit, offset } = pageParams("users");
      const data = await api(`/api/v1/admin/users?limit=${limit}&offset=${offset}&q=${q}`);
      const items = data.items || [];
      const total = data.total || items.length;
      if (!items.length && total === 0) {
        $("usersTable").innerHTML = `<div class="text-sm text-mist">暂无用户</div>`;
        return;
      }
      if (!items.length && total > 0) {
        pages.users = Math.max(1, Math.ceil(total / PAGE_SIZE));
        return loadUsers();
      }
      $("usersTable").innerHTML = withPager(`<div class="overflow-x-auto"><table class="table-base">
        <thead><tr><th>user_id</th><th>昵称</th><th>状态</th><th>操作</th></tr></thead>
        <tbody>${items.map((u) => `<tr>
          <td class="font-mono text-xs">${escapeHtml(u.user_id)}</td>
          <td>${escapeHtml(u.display_name)}</td>
          <td>${statusBadge(u.status)}</td>
          <td>
            <div class="action-row">
              <button type="button" class="btn btn-ghost btn-xs" data-uact="status" data-id="${escapeHtml(u.user_id)}" data-status="${escapeHtml(u.status)}">${u.status === "active" ? "禁用" : "启用"}</button>
              <button type="button" class="btn btn-ghost btn-xs" data-uact="kick" data-id="${escapeHtml(u.user_id)}">强制下线</button>
              <button type="button" class="btn btn-ghost btn-xs" data-uact="sessions" data-id="${escapeHtml(u.user_id)}">会话</button>
              <button type="button" class="btn btn-ghost btn-xs" data-uact="resetmfa" data-id="${escapeHtml(u.user_id)}">重置MFA</button>
              <button type="button" class="btn btn-ghost btn-xs" data-uact="merge" data-id="${escapeHtml(u.user_id)}">合并入</button>
            </div>
          </td>
        </tr>`).join("")}</tbody></table></div>`, "users", total);

      bindPager($("usersTable"), "users", () => loadUsers());
      $("usersTable").querySelectorAll("button[data-uact]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          try {
            if (btn.dataset.uact === "status") {
              const next = btn.dataset.status === "active" ? "disabled" : "active";
              const ok = await uiConfirm(
                next === "disabled" ? "确认禁用该用户？" : "确认启用该用户？",
                { title: "变更用户状态", danger: next === "disabled" }
              );
              if (!ok) return;
              await api(`/api/v1/admin/users/${encodeURIComponent(btn.dataset.id)}/status`, {
                method: "POST", body: JSON.stringify({ status: next }),
              });
              toast(next === "disabled" ? "用户已禁用" : "用户已启用");
            } else if (btn.dataset.uact === "sessions") {
              const data = await api(`/api/v1/admin/users/${encodeURIComponent(btn.dataset.id)}/sessions`);
              const items = data.items || [];
              await uiAlert(
                items.length
                  ? items.map((s) => `${s.device_id || "-"} | ${s.ip} | ${s.jti}`).join("\n")
                  : "无活跃会话",
                { title: "活跃会话", mono: true }
              );
              return;
            } else if (btn.dataset.uact === "resetmfa") {
              const ok = await uiConfirm("确认重置该用户 MFA？用户需重新绑定。", {
                title: "重置 MFA",
                danger: true,
                primaryText: "确认重置",
              });
              if (!ok) return;
              await api(`/api/v1/admin/users/${encodeURIComponent(btn.dataset.id)}/reset-mfa`, {
                method: "POST", body: "{}",
              });
              toast("已重置 MFA");
              return;
            } else if (btn.dataset.uact === "merge") {
              const source = await uiPrompt("输入要并入当前用户的 source_user_id", {
                title: "合并账号",
                placeholder: "source_user_id",
              });
              if (!source) return;
              const ok = await uiConfirm(`确认将 ${source} 合并到 ${btn.dataset.id}？此操作不可逆。`, {
                title: "确认合并",
                danger: true,
                primaryText: "确认合并",
              });
              if (!ok) return;
              await api(`/api/v1/admin/users/merge`, {
                method: "POST",
                body: JSON.stringify({ target_user_id: btn.dataset.id, source_user_id: source }),
              });
              toast("合并完成");
            } else {
              const ok = await uiConfirm("确认强制下线？将吊销该用户全部 refresh token。", {
                title: "强制下线",
                danger: true,
                primaryText: "确认下线",
              });
              if (!ok) return;
              await api(`/api/v1/admin/users/${encodeURIComponent(btn.dataset.id)}/force-logout`, {
                method: "POST", body: "{}",
              });
              toast("已强制下线");
            }
            loadUsers();
          } catch (e) {
            uiAlert(e.message, { title: "操作失败" });
          }
        });
      });
    } catch (e) {
      $("usersTable").innerHTML = `<div class="result warn">${escapeHtml(e.message)}</div>`;
    }
  }

  async function loadAudits({ reset } = {}) {
    if (reset) pages.audits = 1;
    try {
      const { limit, offset } = pageParams("audits");
      const data = await api(`/api/v1/admin/audits?limit=${limit}&offset=${offset}&${auditQuery()}`);
      const items = data.items || [];
      const total = data.total || items.length;
      if (!items.length && total === 0) {
        $("auditsTable").innerHTML = `<div class="text-sm text-mist">暂无审计记录</div>`;
        return;
      }
      if (!items.length && total > 0) {
        pages.audits = Math.max(1, Math.ceil(total / PAGE_SIZE));
        return loadAudits();
      }
      $("auditsTable").innerHTML = withPager(`<div class="overflow-x-auto"><table class="table-base">
        <thead><tr><th>时间</th><th>action</th><th>user</th><th>client</th><th>jti</th><th>device</th><th>成功</th><th>detail</th></tr></thead>
        <tbody>${items.map((a) => `<tr>
          <td class="whitespace-nowrap text-xs">${escapeHtml(a.created_at)}</td>
          <td class="font-mono text-xs">${escapeHtml(a.action)}</td>
          <td class="font-mono text-xs">${escapeHtml(a.user_id)}</td>
          <td class="font-mono text-xs">${escapeHtml(a.client_id)}</td>
          <td class="font-mono text-xs" title="${escapeHtml(a.jti || "")}">${escapeHtml((a.jti || "").slice(0, 12))}${a.jti ? "…" : ""}</td>
          <td class="font-mono text-xs">${escapeHtml(a.device_id || "")}</td>
          <td>${a.success ? `<span class="badge badge-ok">Y</span>` : `<span class="badge badge-warn">N</span>`}</td>
          <td class="text-xs text-mist">${escapeHtml(a.detail)}</td>
        </tr>`).join("")}</tbody></table></div>`, "audits", total);
      bindPager($("auditsTable"), "audits", () => loadAudits());
    } catch (e) {
      $("auditsTable").innerHTML = `<div class="result warn">${escapeHtml(e.message)}</div>`;
    }
  }

  async function loadTenants({ reset } = {}) {
    if (reset) pages.tenants = 1;
    try {
      const { limit, offset } = pageParams("tenants");
      const data = await api(`/api/v1/admin/tenants?limit=${limit}&offset=${offset}`);
      const items = data.items || [];
      const total = data.total || items.length;
      if (!items.length && total === 0) {
        $("tenantsTable").innerHTML = `<div class="text-sm text-mist">暂无租户</div>`;
        return;
      }
      if (!items.length && total > 0) {
        pages.tenants = Math.max(1, Math.ceil(total / PAGE_SIZE));
        return loadTenants();
      }
      $("tenantsTable").innerHTML = withPager(`<div class="grid gap-3">${items.map((t) => `
        <article class="rounded-xl border border-line bg-white p-4">
          <div class="flex flex-wrap items-start justify-between gap-3">
            <div>
              <div class="flex flex-wrap items-center gap-2">
                <h3 class="font-semibold">${escapeHtml(t.name)}</h3>
                ${statusBadge(t.status)}
                <span class="badge badge-muted font-mono">${escapeHtml(t.tenant_id)}</span>
              </div>
              <div class="mt-2 text-xs text-mist">应用 ${t.app_count}/${t.max_apps} · 日发码 ${t.daily_otp_limit} · ForceSSO=${t.force_sso} · 禁密码=${t.disable_local_password}</div>
              <div class="mt-1 font-mono text-xs text-mist">${(t.sso_domains || []).join(", ") || "无 SSO 域名"}</div>
            </div>
            <button type="button" class="btn btn-ghost btn-xs" data-edit-tenant="${escapeHtml(t.tenant_id)}">编辑</button>
          </div>
        </article>`).join("")}</div>`, "tenants", total);
      bindPager($("tenantsTable"), "tenants", () => loadTenants());
      $("tenantsTable").querySelectorAll("[data-edit-tenant]").forEach((btn) => {
        btn.onclick = async () => {
          const t = items.find((x) => x.tenant_id === btn.dataset.editTenant);
          const values = await uiForm("编辑租户", [
            { name: "name", label: "名称", value: t.name, required: true },
            { name: "status", label: "状态", type: "select", value: t.status, options: [{ value: "active" }, { value: "disabled" }] },
            { name: "max_apps", label: "应用上限", value: String(t.max_apps) },
            { name: "daily_otp_limit", label: "日发码上限", value: String(t.daily_otp_limit) },
            { name: "sso_domains", label: "SSO 域名（逗号分隔）", value: (t.sso_domains || []).join(",") },
            { name: "force_sso", label: "强制企业 SSO", type: "checkbox", checked: !!t.force_sso },
            { name: "disable_local_password", label: "禁用本地密码", type: "checkbox", checked: !!t.disable_local_password },
          ]);
          if (!values) return;
          try {
            await api(`/api/v1/admin/tenants/${encodeURIComponent(t.tenant_id)}`, {
              method: "PATCH",
              body: JSON.stringify({
                name: values.name, status: values.status,
                max_apps: Number(values.max_apps), daily_otp_limit: Number(values.daily_otp_limit),
                sso_domains: values.sso_domains.split(",").map((s) => s.trim()).filter(Boolean),
                force_sso: values.force_sso, disable_local_password: values.disable_local_password,
              }),
            });
            toast("租户已更新");
            loadTenants();
          } catch (e) { uiAlert(e.message); }
        };
      });
    } catch (e) {
      $("tenantsTable").innerHTML = `<div class="result warn">${escapeHtml(e.message)}</div>`;
    }
  }

  async function loadIdPs({ reset } = {}) {
    if (reset) pages.idps = 1;
    try {
      const data = await api("/api/v1/admin/enterprise-idps");
      const all = data.items || [];
      const total = all.length;
      const { offset, limit } = pageParams("idps");
      if (total > 0 && offset >= total) {
        pages.idps = Math.max(1, Math.ceil(total / PAGE_SIZE));
        return loadIdPs();
      }
      const items = all.slice(offset, offset + limit);
      $("idpTable").innerHTML = withPager(
        items.length
          ? `<div class="overflow-x-auto"><table class="table-base"><thead><tr><th>域名</th><th>租户</th><th>Provider</th><th>JIT</th><th>操作</th></tr></thead>
        <tbody>${items.map((p) => `<tr>
          <td class="font-mono text-xs">${escapeHtml(p.domain)}</td>
          <td class="font-mono text-xs">${escapeHtml(p.tenant_id)}</td>
          <td>${escapeHtml(p.provider)}</td>
          <td>${p.jit_enabled ? "Y" : "N"}</td>
          <td><button type="button" class="btn btn-ghost btn-xs" data-del-idp="${p.id}">删除</button></td>
        </tr>`).join("")}</tbody></table></div>`
          : "",
        "idps",
        total,
        `<div class="text-sm text-mist">暂无企业 IdP</div>`
      );
      bindPager($("idpTable"), "idps", () => loadIdPs());
      $("idpTable").querySelectorAll("[data-del-idp]").forEach((btn) => {
        btn.onclick = async () => {
          if (!(await uiConfirm("确认删除该 IdP？", { danger: true }))) return;
          try {
            await api(`/api/v1/admin/enterprise-idps/${btn.dataset.delIdp}`, { method: "DELETE" });
            toast("已删除");
            loadIdPs({ reset: true });
          } catch (e) { uiAlert(e.message); }
        };
      });
    } catch (e) {
      $("idpTable").innerHTML = `<div class="result warn">${escapeHtml(e.message)}</div>`;
    }
  }

  async function loadInvites({ reset } = {}) {
    if (reset) pages.invites = 1;
    try {
      const { limit, offset } = pageParams("invites");
      const data = await api(`/api/v1/admin/invites?limit=${limit}&offset=${offset}`);
      const items = data.items || [];
      const total = data.total || items.length;
      if (!items.length && total === 0) {
        $("invitesTable").innerHTML = `<div class="text-sm text-mist">暂无邀请</div>`;
        return;
      }
      if (!items.length && total > 0) {
        pages.invites = Math.max(1, Math.ceil(total / PAGE_SIZE));
        return loadInvites();
      }
      $("invitesTable").innerHTML = withPager(`<div class="overflow-x-auto"><table class="table-base"><thead><tr><th>code</th><th>租户</th><th>用途</th><th>一键链接</th><th>状态</th><th>操作</th></tr></thead>
        <tbody>${items.map((i) => `<tr>
          <td class="font-mono text-xs">${escapeHtml(i.code)}</td>
          <td class="font-mono text-xs">${escapeHtml(i.tenant_id)}</td>
          <td class="text-xs">${i.used_count}/${i.max_uses}${i.email ? " · " + escapeHtml(i.email) : ""}${i.phone ? " · " + escapeHtml(i.phone) : ""}</td>
          <td class="text-xs max-w-[220px] truncate" title="${escapeHtml(i.invite_url || "")}">${escapeHtml(i.invite_url || "-")}</td>
          <td>${statusBadge(i.status === "active" ? "active" : i.status)}</td>
          <td class="action-row">
            <button type="button" class="btn btn-ghost btn-xs" data-copy="${escapeHtml(i.code)}">复制码</button>
            <button type="button" class="btn btn-ghost btn-xs" data-copy-url="${escapeHtml(i.invite_url || "")}" ${i.invite_url ? "" : "disabled"}>复制链接</button>
            <button type="button" class="btn btn-ghost btn-xs" data-revoke-inv="${escapeHtml(i.code)}" ${i.status !== "active" ? "disabled" : ""}>吊销</button>
          </td>
        </tr>`).join("")}</tbody></table></div>`, "invites", total);
      bindPager($("invitesTable"), "invites", () => loadInvites());
      $("invitesTable").querySelectorAll("[data-copy]").forEach((btn) => {
        btn.onclick = async () => toast((await copyText(btn.dataset.copy)) ? "已复制" : "复制失败", "ok");
      });
      $("invitesTable").querySelectorAll("[data-copy-url]").forEach((btn) => {
        btn.onclick = async () => toast((await copyText(btn.dataset.copyUrl)) ? "链接已复制" : "复制失败", "ok");
      });
      $("invitesTable").querySelectorAll("[data-revoke-inv]").forEach((btn) => {
        btn.onclick = async () => {
          if (!(await uiConfirm("确认吊销邀请码？", { danger: true }))) return;
          try {
            await api(`/api/v1/admin/invites/${encodeURIComponent(btn.dataset.revokeInv)}/revoke`, { method: "POST", body: "{}" });
            toast("已吊销");
            loadInvites();
          } catch (e) { uiAlert(e.message); }
        };
      });
    } catch (e) {
      $("invitesTable").innerHTML = `<div class="result warn">${escapeHtml(e.message)}</div>`;
    }
  }

  async function loadJoins({ reset } = {}) {
    if (reset) pages.joins = 1;
    try {
      const { limit, offset } = pageParams("joins");
      const data = await api(`/api/v1/admin/join-requests?status=pending&limit=${limit}&offset=${offset}`);
      const items = data.items || [];
      const total = data.total || items.length;
      if (!items.length && total === 0) {
        $("joinsTable").innerHTML = `<div class="text-sm text-mist">暂无待审批申请</div>`;
        return;
      }
      if (!items.length && total > 0) {
        pages.joins = Math.max(1, Math.ceil(total / PAGE_SIZE));
        return loadJoins();
      }
      $("joinsTable").innerHTML = withPager(`<div class="overflow-x-auto"><table class="table-base"><thead><tr><th>request</th><th>身份</th><th>租户</th><th>时间</th><th>操作</th></tr></thead>
        <tbody>${items.map((j) => `<tr>
          <td class="font-mono text-xs">${escapeHtml(j.request_id)}</td>
          <td>${escapeHtml(j.identity)}</td>
          <td class="font-mono text-xs">${escapeHtml(j.tenant_id)}</td>
          <td class="text-xs">${escapeHtml(j.created_at)}</td>
          <td class="action-row">
            <button type="button" class="btn btn-primary btn-xs" data-join="approve" data-id="${escapeHtml(j.request_id)}">通过</button>
            <button type="button" class="btn btn-ghost btn-xs" data-join="reject" data-id="${escapeHtml(j.request_id)}">拒绝</button>
          </td>
        </tr>`).join("")}</tbody></table></div>`, "joins", total);
      bindPager($("joinsTable"), "joins", () => loadJoins());
      $("joinsTable").querySelectorAll("[data-join]").forEach((btn) => {
        btn.onclick = async () => {
          try {
            await api(`/api/v1/admin/join-requests/${encodeURIComponent(btn.dataset.id)}/review`, {
              method: "POST", body: JSON.stringify({ decision: btn.dataset.join }),
            });
            toast(btn.dataset.join === "approve" ? "已通过" : "已拒绝");
            loadJoins({ reset: true });
          } catch (e) { uiAlert(e.message); }
        };
      });
    } catch (e) {
      $("joinsTable").innerHTML = `<div class="result warn">${escapeHtml(e.message)}</div>`;
    }
  }

  async function loadRoles({ reset } = {}) {
    if (reset) pages.roles = 1;
    try {
      const { limit, offset } = pageParams("roles");
      const data = await api(`/api/v1/admin/roles?limit=${limit}&offset=${offset}`);
      const items = data.items || [];
      const total = data.total || items.length;
      if (!items.length && total === 0) {
        $("rolesTable").innerHTML = `<div class="text-sm text-mist">暂无角色绑定</div>`;
        return;
      }
      if (!items.length && total > 0) {
        pages.roles = Math.max(1, Math.ceil(total / PAGE_SIZE));
        return loadRoles();
      }
      $("rolesTable").innerHTML = withPager(`<div class="overflow-x-auto"><table class="table-base"><thead><tr><th>user_id</th><th>tenant</th><th>role</th><th>操作</th></tr></thead>
        <tbody>${items.map((r) => `<tr>
          <td class="font-mono text-xs">${escapeHtml(r.user_id)}</td>
          <td class="font-mono text-xs">${escapeHtml(r.tenant_id || "(platform)")}</td>
          <td><span class="badge badge-ok">${escapeHtml(r.role)}</span></td>
          <td><button type="button" class="btn btn-ghost btn-xs" data-revoke-role data-user="${escapeHtml(r.user_id)}" data-tenant="${escapeHtml(r.tenant_id || "")}" data-role="${escapeHtml(r.role)}">移除</button></td>
        </tr>`).join("")}</tbody></table></div>`, "roles", total);
      bindPager($("rolesTable"), "roles", () => loadRoles());
      $("rolesTable").querySelectorAll("[data-revoke-role]").forEach((btn) => {
        btn.onclick = async () => {
          if (!(await uiConfirm("确认移除该角色？", { danger: true }))) return;
          try {
            await api("/api/v1/admin/roles/revoke", {
              method: "POST",
              body: JSON.stringify({ user_id: btn.dataset.user, tenant_id: btn.dataset.tenant, role: btn.dataset.role }),
            });
            toast("已移除");
            loadRoles({ reset: true });
          } catch (e) { uiAlert(e.message); }
        };
      });
    } catch (e) {
      $("rolesTable").innerHTML = `<div class="result warn">${escapeHtml(e.message)}</div>`;
    }
  }

  function fillClientSelect() {
    const sel = $("testClientId");
    const current = sel.value;
    const list = (state.appsForSelect && state.appsForSelect.length) ? state.appsForSelect : state.apps;
    sel.innerHTML = list
      .map((a) => `<option value="${escapeHtml(a.client_id)}">${escapeHtml(a.name)} (${escapeHtml(a.client_id)})</option>`)
      .join("");
    if (current) sel.value = current;
  }

  function preparePlayground() {
    if (!state.channels.length) {
      loadChannels().then(() => {
        fillMethodSelect();
        onMethodChange();
      });
    } else {
      fillMethodSelect();
      onMethodChange();
    }
    loadAppsForSelect();
  }

  function fillMethodSelect() {
    $("testMethod").innerHTML = state.channels
      .map((c) => `<option value="${c.method}">${c.name} (${c.method})</option>`)
      .join("");
    const oauth = state.channels.find((c) => c.method === "oauth2");
    $("testProvider").innerHTML = ((oauth && oauth.providers) || ["github"])
      .map((p) => `<option value="${p}">${p}</option>`)
      .join("");
  }

  function onMethodChange() {
    const method = $("testMethod").value;
    const isOTP = method === "phone_otp" || method === "email_otp";
    const isPwd = method === "phone_password" || method === "email_password";
    const isOAuth = method === "oauth2";
    $("otpBlock").classList.toggle("hidden", !isOTP);
    $("pwdBlock").classList.toggle("hidden", !isPwd);
    $("oauthBlock").classList.toggle("hidden", !isOAuth);
    $("oauthProviderRow").classList.toggle("hidden", !isOAuth);
    $("identityLabel").textContent = isOAuth ? "Identity（OAuth 可留空）" : method.includes("email") ? "邮箱" : "手机号";
    $("testIdentity").classList.toggle("hidden", isOAuth);
  }

  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => switchView(btn.dataset.view));
  });

  document.querySelectorAll("[data-login-mode]").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("[data-login-mode]").forEach((el) => {
        el.classList.toggle("active", el === btn);
      });
      const mode = btn.dataset.loginMode;
      $("loginFormToken").classList.toggle("hidden", mode !== "token");
      $("loginFormPassword").classList.toggle("hidden", mode !== "password");
      $("loginError").classList.add("hidden");
    });
  });

  $("loginFormToken").addEventListener("submit", async (e) => {
    e.preventDefault();
    const token = $("loginToken").value.trim();
    if (!token) return;
    try {
      const res = await fetch("/api/v1/admin/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: "token", token }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok || body.code !== 0) {
        showLogin(body.message || "登录失败");
        return;
      }
      await enterConsole(body.data);
      toast("登录成功");
    } catch (err) {
      showLogin(err.message || "网络错误");
    }
  });

  $("loginFormPassword").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const res = await fetch("/api/v1/admin/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          mode: "password",
          method: $("loginMethod").value,
          identity: $("loginIdentity").value.trim(),
          password: $("loginPassword").value,
          tenant_id: $("loginTenant").value.trim() || "default",
        }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok || body.code !== 0) {
        showLogin(body.message || "登录失败");
        return;
      }
      await enterConsole(body.data);
      toast("登录成功");
    } catch (err) {
      showLogin(err.message || "网络错误");
    }
  });

  $("btnLogout").addEventListener("click", async () => {
    const ok = await uiConfirm("确定退出管理后台？", { primaryText: "退出" });
    if (!ok) return;
    showLogin();
    toast("已退出登录");
  });

  $("refreshApps").addEventListener("click", () => loadApps({ reset: true }));
  $("refreshUsers")?.addEventListener("click", () => loadUsers({ reset: true }));
  $("userQuery")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      loadUsers({ reset: true });
    }
  });
  $("refreshAudits")?.addEventListener("click", () => loadAudits({ reset: true }));
  $("exportAudits")?.addEventListener("click", () => exportAudits(false));
  $("persistAudits")?.addEventListener("click", () => exportAudits(true));
  $("refreshWebhooks")?.addEventListener("click", loadWebhooks);
  $("webhookForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const events = String(fd.get("events") || "").split(",").map((x) => x.trim()).filter(Boolean);
    try {
      await api("/api/v1/admin/webhooks", {
        method: "POST",
        body: JSON.stringify({
          name: fd.get("name"),
          url: fd.get("url"),
          secret: fd.get("secret") || undefined,
          events,
        }),
      });
      toast("Webhook 已创建");
      e.target.reset();
      loadWebhooks();
    } catch (err) { uiAlert(err.message); }
  });
  $("refreshDashboard")?.addEventListener("click", loadDashboard);
  $("dashTenant")?.addEventListener("change", loadDashboard);
  $("refreshSMS")?.addEventListener("click", loadSMSChannel);
  $("refreshJWTKeys")?.addEventListener("click", loadJWTKeys);
  $("refreshTenants")?.addEventListener("click", () => loadTenants({ reset: true }));
  $("refreshInvites")?.addEventListener("click", () => loadInvites({ reset: true }));
  $("refreshJoins")?.addEventListener("click", () => loadJoins({ reset: true }));
  $("refreshRoles")?.addEventListener("click", () => loadRoles({ reset: true }));

  document.querySelectorAll("[data-subtabs]").forEach((viewEl) => {
    viewEl.querySelectorAll(".subtab").forEach((btn) => {
      btn.addEventListener("click", () => {
        activateSubTab(viewEl, btn.dataset.subtab, { load: true });
      });
    });
  });

  $("btnCreateTenant")?.addEventListener("click", async () => {
    const values = await uiForm("新建租户", [
      { name: "tenant_id", label: "tenant_id（可空自动生成）", placeholder: "acme" },
      { name: "name", label: "名称", required: true, placeholder: "Acme Corp" },
      { name: "max_apps", label: "应用上限", value: "20" },
      { name: "daily_otp_limit", label: "日发码上限", value: "5000" },
    ]);
    if (!values) return;
    try {
      await api("/api/v1/admin/tenants", {
        method: "POST",
        body: JSON.stringify({
          tenant_id: values.tenant_id || undefined,
          name: values.name,
          max_apps: Number(values.max_apps),
          daily_otp_limit: Number(values.daily_otp_limit),
        }),
      });
      toast("租户已创建");
      loadTenants({ reset: true });
    } catch (e) { uiAlert(e.message); }
  });

  $("btnUpsertIdP")?.addEventListener("click", async () => {
    const values = await uiForm("企业 SSO 域名路由", [
      { name: "tenant_id", label: "tenant_id", required: true, value: "default" },
      { name: "domain", label: "邮箱域名", required: true, placeholder: "acme.com" },
      { name: "provider", label: "OAuth Provider 名", required: true, placeholder: "github" },
      { name: "jit_enabled", label: "JIT 自动建用户", type: "checkbox", checked: true },
    ]);
    if (!values) return;
    try {
      await api("/api/v1/admin/enterprise-idps", {
        method: "PUT",
        body: JSON.stringify({
          tenant_id: values.tenant_id, domain: values.domain, provider: values.provider, jit_enabled: values.jit_enabled,
        }),
      });
      toast("IdP 已保存");
      loadIdPs({ reset: true });
    } catch (e) { uiAlert(e.message); }
  });

  $("btnCreateInvite")?.addEventListener("click", async () => {
    const values = await uiForm("创建邀请码", [
      { name: "tenant_id", label: "tenant_id", value: "default" },
      { name: "client_id", label: "client_id（可空）", placeholder: "app_demo" },
      { name: "email", label: "限定邮箱（可空）" },
      { name: "phone", label: "限定手机（可空）" },
      { name: "max_uses", label: "可用次数", value: "1" },
      { name: "expire_in", label: "有效期秒数（0=不过期）", value: "604800" },
      { name: "note", label: "备注" },
    ]);
    if (!values) return;
    try {
      const data = await api("/api/v1/admin/invites", {
        method: "POST",
        body: JSON.stringify({
          tenant_id: values.tenant_id, client_id: values.client_id,
          email: values.email, phone: values.phone,
          max_uses: Number(values.max_uses), expire_in: Number(values.expire_in), note: values.note,
        }),
      });
      await uiAlert(`邀请码：${data.code}`, { title: "创建成功", mono: true });
      loadInvites({ reset: true });
    } catch (e) { uiAlert(e.message); }
  });

  $("btnCreateUser")?.addEventListener("click", async () => {
    const values = await uiForm("管理员创建用户", [
      { name: "tenant_id", label: "tenant_id", value: "default" },
      { name: "phone", label: "手机号" },
      { name: "email", label: "邮箱" },
      { name: "display_name", label: "昵称" },
      { name: "password", label: "初始密码（可空自动生成）", type: "password" },
      { name: "role", label: "角色", type: "select", value: "user", options: [
        { value: "user" }, { value: "viewer" }, { value: "operator" }, { value: "tenant_admin" }, { value: "platform_admin" },
      ] },
    ]);
    if (!values) return;
    try {
      const data = await api("/api/v1/admin/users", {
        method: "POST",
        body: JSON.stringify({
          tenant_id: values.tenant_id, phone: values.phone, email: values.email,
          display_name: values.display_name, password: values.password, roles: [values.role],
        }),
      });
      await uiAlert(`user_id: ${data.user_id}\n${data.temp_password ? "临时密码: " + data.temp_password : "已使用指定密码"}`, {
        title: "用户已创建", mono: true,
      });
    } catch (e) { uiAlert(e.message); }
  });

  $("btnAssignRole")?.addEventListener("click", async () => {
    const values = await uiForm("分配角色", [
      { name: "user_id", label: "user_id", required: true },
      { name: "tenant_id", label: "tenant_id（platform_admin 可空）", value: "default" },
      { name: "role", label: "角色", type: "select", value: "operator", options: [
        { value: "user" }, { value: "viewer" }, { value: "operator" }, { value: "tenant_admin" }, { value: "platform_admin" },
      ] },
    ]);
    if (!values) return;
    try {
      await api("/api/v1/admin/roles/assign", {
        method: "POST",
        body: JSON.stringify(values),
      });
      toast("角色已分配");
      loadRoles({ reset: true });
    } catch (e) { uiAlert(e.message); }
  });

  $("unlockRiskForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await api("/api/v1/admin/risk/unlock", {
        method: "POST",
        body: JSON.stringify({
          kind: $("unlockKind").value,
          key: $("unlockKey").value.trim(),
        }),
      });
      toast("已解除锁定");
      $("unlockKey").value = "";
    } catch (err) {
      uiAlert(err.message, { title: "解锁失败" });
    }
  });
  $("testMethod").addEventListener("change", onMethodChange);

  $("createAppForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const methods = [...e.target.querySelectorAll('input[name="methods"]:checked')].map((x) => x.value);
    const redirects = String(fd.get("redirect_uris") || "")
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    const cors = String(fd.get("cors_origins") || "")
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    const payload = {
      name: fd.get("name"),
      tenant_id: fd.get("tenant_id") || "default",
      client_id: fd.get("client_id") || undefined,
      client_secret: fd.get("client_secret") || undefined,
      allowed_methods: methods,
      redirect_uris: redirects,
      cors_origins: cors,
      auto_register: !!fd.get("auto_register"),
    };
    try {
      const data = await api("/api/v1/admin/apps", { method: "POST", body: JSON.stringify(payload) });
      state.revealedSecrets[data.client_id] = data.client_secret;
      $("createResult").classList.remove("hidden");
      $("createResult").className = "result";
      $("createResult").innerHTML = `
        <div class="font-semibold">创建成功，凭证也可在右侧列表中随时查看</div>
        <div class="mt-2 font-mono text-xs">client_id: ${escapeHtml(data.client_id)}</div>
        <div class="font-mono text-xs">client_secret: ${escapeHtml(data.client_secret)}</div>`;
      e.target.reset();
      renderMethodChecks();
      toast("应用创建成功");
      loadApps({ reset: true });
      loadAppsForSelect();
    } catch (err) {
      $("createResult").classList.remove("hidden");
      $("createResult").className = "result warn";
      $("createResult").textContent = err.message;
    }
  });

  $("btnChallenge").addEventListener("click", async () => {
    try {
      const body = await authAPI("/api/v1/auth/challenge", {
        method: "POST",
        clientId: $("testClientId").value,
        clientSecret: $("testClientSecret").value.trim(),
        body: {
          method: $("testMethod").value,
          identity: $("testIdentity").value.trim(),
          scene: "login",
        },
      });
      setOutput(body);
      if (body.code === 0 && body.data) {
        $("testChallengeId").value = body.data.challenge_id || "";
        toast("验证码已发送");
      } else {
        toast(body.message || "发码失败", "err");
      }
    } catch (e) {
      setOutput(e.message);
    }
  });

  $("btnOAuthStart").addEventListener("click", async () => {
    const provider = $("testProvider").value;
    const redirect = encodeURIComponent($("testRedirectUri").value.trim());
    const url = `/api/v1/auth/oauth/${provider}/start?redirect_uri=${redirect}&state=admin_test`;
    const headers = { "X-Client-Id": $("testClientId").value };
    const secret = $("testClientSecret").value.trim();
    if (secret) headers["X-Client-Secret"] = secret;
    const res = await fetch(url, { headers });
    const body = await res.json();
    setOutput(body);
    if (body.code === 0 && body.data) {
      $("testAuthURL").value = body.data.authorize_url || "";
      window.__oauthState = body.data.state || "";
    }
  });

  $("btnLogin").addEventListener("click", async () => {
    const method = $("testMethod").value;
    let payload = { method, identity: $("testIdentity").value.trim(), credential: {} };
    if (method === "phone_otp" || method === "email_otp") {
      payload.credential = {
        challenge_id: $("testChallengeId").value.trim(),
        otp: $("testOTP").value.trim(),
      };
    } else if (method === "phone_password" || method === "email_password") {
      payload.credential = { password: $("testPassword").value };
    } else if (method === "oauth2") {
      payload = {
        method: "oauth2",
        provider: $("testProvider").value,
        credential: {
          code: $("testOAuthCode").value.trim(),
          redirect_uri: $("testRedirectUri").value.trim(),
          state: window.__oauthState || "",
          code_verifier: $("testCodeVerifier").value.trim(),
        },
      };
    }
    const body = await authAPI("/api/v1/auth/login", {
      method: "POST",
      clientId: $("testClientId").value,
      clientSecret: $("testClientSecret").value.trim(),
      body: payload,
    });
    setOutput(body);
    if (body.code === 0 && body.data && body.data.token) {
      $("tokenBox").classList.remove("hidden");
      $("accessTokenOut").value = body.data.token.access_token || "";
      $("refreshTokenOut").value = body.data.token.refresh_token || "";
      toast("登录成功");
    } else {
      toast(body.message || "登录失败", "err");
    }
  });

  $("btnMe").addEventListener("click", async () => {
    const res = await fetch("/api/v1/auth/me", {
      headers: {
        "X-Client-Id": $("testClientId").value,
        Authorization: `Bearer ${$("accessTokenOut").value}`,
      },
    });
    setOutput(await res.json());
  });

  $("btnRefresh").addEventListener("click", async () => {
    const body = await authAPI("/api/v1/auth/token/refresh", {
      method: "POST",
      clientId: $("testClientId").value,
      clientSecret: $("testClientSecret").value.trim(),
      body: { refresh_token: $("refreshTokenOut").value },
    });
    setOutput(body);
    if (body.code === 0 && body.data) {
      $("accessTokenOut").value = body.data.access_token || "";
      $("refreshTokenOut").value = body.data.refresh_token || "";
      toast("Token 已刷新");
    }
  });

  restoreSession();
})();
