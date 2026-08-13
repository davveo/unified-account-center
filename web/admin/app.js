(() => {
  const TOKEN_KEY = "uac_admin_token";
  const titles = {
    apps: ["应用凭证", "创建 / 停用应用，调整登录方式，轮换 client_secret"],
    channels: ["对接渠道", "查看中台已支持的登录方式与配置状态"],
    users: ["用户管理", "禁用/强退、重置 MFA、合并账号、风控解锁"],
    audits: ["审计日志", "查询登录 / 绑定 / 改密等操作记录"],
    playground: ["渠道测试", "用真实接口联调验证码 / 密码 / OAuth 登录"],
  };

  const state = {
    channels: [],
    apps: [],
  };

  const $ = (id) => document.getElementById(id);

  function adminToken() {
    return localStorage.getItem(TOKEN_KEY) || $("adminToken").value.trim();
  }

  function setOutput(obj) {
    $("testOutput").textContent = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
  }

  async function api(path, options = {}) {
    const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
    headers["X-Admin-Token"] = adminToken();
    const res = await fetch(path, { ...options, headers });
    const body = await res.json().catch(() => ({}));
    if (!res.ok || body.code !== 0) {
      const msg = body.message || res.statusText || "请求失败";
      throw new Error(msg);
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
    const data = await res.json().catch(() => ({}));
    return data;
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
    if (name === "channels") loadChannels();
    if (name === "playground") preparePlayground();
    if (name === "apps") loadApps();
    if (name === "users") loadUsers();
    if (name === "audits") loadAudits();
  }

  function renderMethodChecks(selected) {
    const defaults = ["phone_otp", "phone_password", "email_otp", "email_password"];
    const methods = state.channels.length
      ? state.channels.map((c) => c.method)
      : defaults;
    $("methodChecks").innerHTML = methods
      .map((m) => {
        const checked = (selected || defaults).includes(m) ? "checked" : "";
        return `<label><input type="checkbox" name="methods" value="${m}" ${checked}/> ${m}</label>`;
      })
      .join("");
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
        oauthHTML = `<div class="card" style="grid-column:1/-1">
          <h3>OAuth Provider（可热更新）</h3>
          <p class="muted">PUT /api/v1/admin/oauth-providers 写入后立即生效，无需发版。</p>
          <div class="mono">${items.map((p) => `${p.name} [${p.kind||"generic"}] client_id=${p.client_id||"-"} enabled=${p.enabled}`).join("<br/>") || "暂无"}</div>
          <button id="upsertOAuthBtn" class="btn btn-ghost" style="margin-top:8px">新增/更新 Provider</button>
        </div>`;
      } catch (_) {}
      $("channelsGrid").innerHTML = state.channels
        .map((ch) => {
          const status = ch.method === "oauth2"
            ? (ch.configured
              ? `<span class="badge ok">已配置 Provider</span>`
              : `<span class="badge warn">未配置 OAuth 密钥</span>`)
            : `<span class="badge ok">可用</span>`;
          const providers = (ch.providers || []).length
            ? `<div class="muted mono">${ch.providers.join(", ")}</div>`
            : "";
          return `<div class="card">
            <h3>${ch.name}</h3>
            <div>${status}<span class="badge">${ch.category}</span></div>
            <p class="muted">${ch.description}</p>
            <div class="mono">${ch.method}</div>
            ${providers}
          </div>`;
        })
        .join("") + oauthHTML;
      const btn = $("upsertOAuthBtn");
      if (btn) {
        btn.onclick = async () => {
          const name = prompt("provider name（如 wechat / github）");
          if (!name) return;
          const kind = prompt("kind: generic | wechat | wecom", name === "wechat" ? "wechat" : "generic") || "generic";
          const clientId = prompt("client_id / appid / corpid") || "";
          const secret = prompt("client_secret（可空表示不改）") || "";
          await api("/api/v1/admin/oauth-providers", {
            method: "PUT",
            body: JSON.stringify({ name, kind, client_id: clientId, client_secret: secret, enabled: true }),
          });
          loadChannels();
        };
      }
    } catch (e) {
      $("channelsGrid").innerHTML = `<div class="result warn">${e.message}</div>`;
    }
  }

  async function loadApps() {
    try {
      const data = await api("/api/v1/admin/apps");
      state.apps = data.items || [];
      if (!state.apps.length) {
        $("appsTable").innerHTML = `<div class="muted">暂无应用，请先创建。</div>`;
        return;
      }
      $("appsTable").innerHTML = `<table>
        <thead><tr>
          <th>名称</th><th>client_id</th><th>登录方式</th><th>状态</th><th>操作</th>
        </tr></thead>
        <tbody>
          ${state.apps
            .map(
              (a) => `<tr>
              <td>${escapeHtml(a.name)}</td>
              <td class="mono">${escapeHtml(a.client_id)}</td>
              <td class="mono">${(a.allowed_methods || []).join(", ")}</td>
              <td>${escapeHtml(a.status)}</td>
              <td>
                <button class="btn btn-ghost" data-act="toggle" data-id="${escapeHtml(a.client_id)}" data-status="${escapeHtml(a.status)}">${a.status === "active" ? "停用" : "启用"}</button>
                <button class="btn btn-ghost" data-act="methods" data-id="${escapeHtml(a.client_id)}">改方式</button>
                <button class="btn btn-ghost" data-act="brand" data-id="${escapeHtml(a.client_id)}">主题</button>
                <button class="btn btn-ghost" data-act="rotate" data-id="${escapeHtml(a.client_id)}">轮换密钥</button>
                <a class="btn btn-ghost" href="/login?client_id=${encodeURIComponent(a.client_id)}&redirect_uri=${encodeURIComponent((a.redirect_uris||[])[0]||'')}" target="_blank">托管登录</a>
              </td>
            </tr>`
            )
            .join("")}
        </tbody>
      </table>`;
      fillClientSelect();
      $("appsTable").querySelectorAll("button[data-act]").forEach((btn) => {
        btn.addEventListener("click", () => onAppAction(btn.dataset.act, btn.dataset.id, btn.dataset.status));
      });
    } catch (e) {
      $("appsTable").innerHTML = `<div class="result warn">${e.message}</div>`;
    }
  }

  async function onAppAction(act, clientId, status) {
    try {
      if (act === "toggle") {
        const next = status === "active" ? "disabled" : "active";
        await api(`/api/v1/admin/apps/${encodeURIComponent(clientId)}`, {
          method: "PATCH",
          body: JSON.stringify({ status: next }),
        });
        loadApps();
      } else if (act === "methods") {
        const raw = prompt("输入 allowed_methods，逗号分隔", "phone_otp,email_otp,phone_password,email_password");
        if (!raw) return;
        await api(`/api/v1/admin/apps/${encodeURIComponent(clientId)}`, {
          method: "PATCH",
          body: JSON.stringify({ allowed_methods: raw.split(",").map((s) => s.trim()).filter(Boolean) }),
        });
        loadApps();
      } else if (act === "brand") {
        const title = prompt("登录页标题", "欢迎登录");
        if (title == null) return;
        const logo = prompt("Logo URL（可空）", "") || "";
        const color = prompt("主题色", "#1f6feb") || "#1f6feb";
        const pkce = confirm("是否强制 PKCE？");
        await api(`/api/v1/admin/apps/${encodeURIComponent(clientId)}`, {
          method: "PATCH",
          body: JSON.stringify({ login_title: title, logo_url: logo, theme_color: color, require_pkce: pkce }),
        });
        loadApps();
      } else if (act === "rotate") {
        if (!confirm("确认轮换密钥？旧 secret 立即失效。")) return;
        const data = await api(`/api/v1/admin/apps/${encodeURIComponent(clientId)}/rotate-secret`, { method: "POST", body: "{}" });
        alert(`新 client_secret（仅显示一次）:\n${data.client_secret}`);
      }
    } catch (e) {
      alert(e.message);
    }
  }

  async function loadUsers() {
    try {
      const q = encodeURIComponent($("userQuery").value.trim());
      const data = await api(`/api/v1/admin/users?limit=50&q=${q}`);
      const items = data.items || [];
      $("usersTable").innerHTML = `<table>
        <thead><tr><th>user_id</th><th>昵称</th><th>状态</th><th>操作</th></tr></thead>
        <tbody>${items.map((u) => `<tr>
          <td class="mono">${escapeHtml(u.user_id)}</td>
          <td>${escapeHtml(u.display_name)}</td>
          <td>${escapeHtml(u.status)}</td>
          <td>
            <button class="btn btn-ghost" data-uact="status" data-id="${escapeHtml(u.user_id)}" data-status="${escapeHtml(u.status)}">${u.status === "active" ? "禁用" : "启用"}</button>
            <button class="btn btn-ghost" data-uact="kick" data-id="${escapeHtml(u.user_id)}">强制下线</button>
            <button class="btn btn-ghost" data-uact="sessions" data-id="${escapeHtml(u.user_id)}">会话</button>
            <button class="btn btn-ghost" data-uact="resetmfa" data-id="${escapeHtml(u.user_id)}">重置MFA</button>
            <button class="btn btn-ghost" data-uact="merge" data-id="${escapeHtml(u.user_id)}">合并入</button>
          </td>
        </tr>`).join("")}</tbody></table>`;
      $("usersTable").querySelectorAll("button[data-uact]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          try {
            if (btn.dataset.uact === "status") {
              const next = btn.dataset.status === "active" ? "disabled" : "active";
              await api(`/api/v1/admin/users/${encodeURIComponent(btn.dataset.id)}/status`, {
                method: "POST", body: JSON.stringify({ status: next }),
              });
            } else if (btn.dataset.uact === "sessions") {
              const data = await api(`/api/v1/admin/users/${encodeURIComponent(btn.dataset.id)}/sessions`);
              const items = data.items || [];
              alert(items.length ? items.map((s) => `${s.device_id || "-"} | ${s.ip} | ${s.jti}`).join("\n") : "无活跃会话");
              return;
            } else if (btn.dataset.uact === "resetmfa") {
              if (!confirm("确认重置该用户 MFA？")) return;
              await api(`/api/v1/admin/users/${encodeURIComponent(btn.dataset.id)}/reset-mfa`, { method: "POST", body: "{}" });
              alert("已重置 MFA");
              return;
            } else if (btn.dataset.uact === "merge") {
              const source = prompt("输入要并入当前用户的 source_user_id");
              if (!source) return;
              await api(`/api/v1/admin/users/merge`, {
                method: "POST",
                body: JSON.stringify({ target_user_id: btn.dataset.id, source_user_id: source }),
              });
              alert("合并完成");
            } else {
              await api(`/api/v1/admin/users/${encodeURIComponent(btn.dataset.id)}/force-logout`, {
                method: "POST", body: "{}",
              });
              alert("已吊销该用户全部 refresh token");
            }
            loadUsers();
          } catch (e) { alert(e.message); }
        });
      });
    } catch (e) {
      $("usersTable").innerHTML = `<div class="result warn">${e.message}</div>`;
    }
  }

  async function loadAudits() {
    try {
      const user = encodeURIComponent($("auditUser").value.trim());
      const action = encodeURIComponent($("auditAction").value.trim());
      const data = await api(`/api/v1/admin/audits?limit=50&user_id=${user}&action=${action}`);
      const items = data.items || [];
      $("auditsTable").innerHTML = `<table>
        <thead><tr><th>时间</th><th>action</th><th>user</th><th>client</th><th>成功</th><th>detail</th></tr></thead>
        <tbody>${items.map((a) => `<tr>
          <td>${escapeHtml(a.created_at)}</td>
          <td class="mono">${escapeHtml(a.action)}</td>
          <td class="mono">${escapeHtml(a.user_id)}</td>
          <td class="mono">${escapeHtml(a.client_id)}</td>
          <td>${a.success ? "Y" : "N"}</td>
          <td>${escapeHtml(a.detail)}</td>
        </tr>`).join("")}</tbody></table>`;
    } catch (e) {
      $("auditsTable").innerHTML = `<div class="result warn">${e.message}</div>`;
    }
  }

  function fillClientSelect() {
    const sel = $("testClientId");
    const current = sel.value;
    sel.innerHTML = state.apps
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
    if (!state.apps.length) loadApps();
    else fillClientSelect();
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

  function escapeHtml(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // events
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => switchView(btn.dataset.view));
  });

  $("adminToken").value = localStorage.getItem(TOKEN_KEY) || "admin-dev-token";
  $("saveToken").addEventListener("click", () => {
    localStorage.setItem(TOKEN_KEY, $("adminToken").value.trim());
    alert("已保存 Admin Token");
  });

  $("refreshApps").addEventListener("click", loadApps);
  $("refreshUsers")?.addEventListener("click", loadUsers);
  $("refreshAudits")?.addEventListener("click", loadAudits);
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
      alert("已解除锁定");
      $("unlockKey").value = "";
    } catch (err) {
      alert(err.message);
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
    const payload = {
      name: fd.get("name"),
      client_id: fd.get("client_id") || undefined,
      client_secret: fd.get("client_secret") || undefined,
      allowed_methods: methods,
      redirect_uris: redirects,
      auto_register: !!fd.get("auto_register"),
    };
    try {
      const data = await api("/api/v1/admin/apps", { method: "POST", body: JSON.stringify(payload) });
      $("createResult").classList.remove("hidden");
      $("createResult").className = "result";
      $("createResult").innerHTML = `
        <div><strong>创建成功（请立即保存 secret，之后无法再查看明文）</strong></div>
        <div class="mono">client_id: ${escapeHtml(data.client_id)}</div>
        <div class="mono">client_secret: ${escapeHtml(data.client_secret)}</div>`;
      e.target.reset();
      renderMethodChecks();
      loadApps();
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
    }
  });

  // init
  loadChannels().then(() => {
    renderMethodChecks();
    loadApps();
  });
})();
