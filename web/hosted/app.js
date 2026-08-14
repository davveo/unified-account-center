(() => {
  const qs = new URLSearchParams(location.search);
  const clientId = qs.get("client_id") || "";
  const redirectURI = qs.get("redirect_uri") || "";
  const state = qs.get("state") || "";
  const codeChallenge = qs.get("code_challenge") || "";
  const deviceId = qs.get("device_id") || ("web_" + Math.random().toString(36).slice(2, 10));

  const inviteCode = qs.get("invite_code") || "";
  const hintEmail = qs.get("hint_email") || "";

  const $ = (id) => document.getElementById(id);
  const errBox = $("err");
  let cfg = null;
  let method = "";

  function showErr(msg) {
    errBox.textContent = msg || "";
    errBox.classList.toggle("hidden", !msg);
  }

  let mfaToken = "";

  async function api(path, opts = {}) {
    const headers = Object.assign({ "Content-Type": "application/json", "X-Client-Id": clientId }, opts.headers || {});
    const res = await fetch(path, Object.assign({}, opts, { headers }));
    const body = await res.json();
    if (body.code !== 0) {
      const err = new Error(body.message || "请求失败");
      err.code = body.code;
      err.data = body.data;
      throw err;
    }
    return body.data;
  }

  function methodLabel(m) {
    return ({
      phone_otp: "手机验证码",
      email_otp: "邮箱验证码",
      phone_password: "手机密码",
      email_password: "邮箱密码",
      oauth2: "第三方",
      passkey: "Passkey",
    })[m] || m;
  }

  async function finishWithLogin(login) {
    const token = login.token || {};
    if (token.must_change_password || token.password_expired) {
      const u = new URL("/account/", location.origin);
      u.searchParams.set("client_id", clientId);
      u.searchParams.set("access_token", token.access_token || "");
      u.searchParams.set("force", "1");
      location.href = u.toString();
      return;
    }
    if (!redirectURI) {
      showErr("登录成功，但缺少 redirect_uri，无法回跳");
      console.log(login);
      return;
    }
    const issued = await api("/api/v1/auth/hosted/code", {
      method: "POST",
      headers: { Authorization: "Bearer " + token.access_token },
      body: JSON.stringify({
        redirect_uri: redirectURI,
        state,
        code_challenge: codeChallenge,
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        id_token: token.id_token,
        expire_in: token.expire_in,
        refresh_expire_in: token.refresh_expire_in,
        device_id: token.device_id || deviceId,
        refresh_jti: token.refresh_jti,
      }),
    });
    const u = new URL(issued.redirect_uri || redirectURI);
    u.searchParams.set("code", issued.code);
    if (issued.state || state) u.searchParams.set("state", issued.state || state);
    location.href = u.toString();
  }

  function showMFA(token) {
    mfaToken = token;
    $("loginForm").classList.add("hidden");
    $("oauthBlock").classList.add("hidden");
    $("methodTabs").classList.add("hidden");
    $("mfaForm").classList.remove("hidden");
    $("mfaCode").focus();
  }

  function selectMethod(m) {
    method = m;
    document.querySelectorAll(".tab").forEach((el) => el.classList.toggle("active", el.dataset.m === m));
    const otp = m.endsWith("_otp");
    const pwd = m.endsWith("_password");
    const isOAuth = m === "oauth2";
    const isPasskey = m === "passkey";
    $("otpBlock").classList.toggle("hidden", !otp);
    $("pwdBlock").classList.toggle("hidden", !pwd);
    $("loginForm").classList.toggle("hidden", isOAuth || isPasskey);
    $("oauthBlock").classList.toggle("hidden", !isOAuth);
    $("passkeyBlock").classList.toggle("hidden", !isPasskey);
    $("identityLabel").textContent = m.startsWith("email") ? "邮箱" : "手机号";
  }

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

  async function load() {
    if (!clientId) {
      showErr("缺少 client_id");
      return;
    }
    cfg = await api(`/api/v1/auth/hosted/config?client_id=${encodeURIComponent(clientId)}`);
    document.documentElement.style.setProperty("--accent", cfg.theme_color || "#1f6feb");
    $("title").textContent = cfg.login_title || cfg.name || "登录";
    $("subtitle").textContent = cfg.name || "统一账户中台";
    if (cfg.logo_url) {
      $("logo").src = cfg.logo_url;
      $("logo").classList.remove("hidden");
    }
    const tabs = $("methodTabs");
    tabs.innerHTML = "";
    (cfg.allowed_methods || []).forEach((m) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "tab";
      b.dataset.m = m;
      b.textContent = methodLabel(m);
      b.onclick = () => selectMethod(m);
      tabs.appendChild(b);
    });
    const oauthBox = $("oauthBlock");
    oauthBox.innerHTML = "";
    (cfg.oauth_providers || []).forEach((p) => {
      const a = document.createElement("a");
      a.href = `#oauth-${p}`;
      a.textContent = `使用 ${p} 登录`;
      a.onclick = async (e) => {
        e.preventDefault();
        try {
          const start = await api(`/api/v1/auth/oauth/${encodeURIComponent(p)}/start?redirect_uri=${encodeURIComponent(redirectURI)}&state=${encodeURIComponent(state)}&code_challenge=${encodeURIComponent(codeChallenge)}`);
          location.href = start.authorize_url;
        } catch (err) {
          showErr(err.message);
        }
      };
      oauthBox.appendChild(a);
    });
    if (hintEmail) {
      $("identity").value = hintEmail;
      $("ssoEmail").value = hintEmail;
    }
    const first = (cfg.allowed_methods || [])[0];
    if (first) selectMethod(first);
    if (hintEmail) {
      if ((cfg.allowed_methods || []).includes("email_otp")) selectMethod("email_otp");
      else if ((cfg.allowed_methods || []).includes("email_password")) selectMethod("email_password");
    }
    if (inviteCode) {
      $("subtitle").textContent = (cfg.name || "统一账户中台") + " · 邀请注册";
    }
  }

  $("btnSSO").onclick = async () => {
    showErr("");
    try {
      const email = ($("ssoEmail").value || $("identity").value || "").trim();
      if (!email) { showErr("请输入企业邮箱"); return; }
      const data = await api("/api/v1/auth/sso/discover", {
        method: "POST",
        body: JSON.stringify({ email }),
      });
      const box = $("ssoResult");
      if (!data || (!data.provider && !data.saml && !data.redirect_url && !data.domain)) {
        box.textContent = "未发现企业 SSO 配置";
        return;
      }
      const domain = data.domain || email.split("@")[1] || "";
      if (data.protocol === "saml" || data.saml || (data.provider && String(data.provider).includes("saml"))) {
        box.innerHTML = `<a href="/api/v1/auth/saml/start?domain=${encodeURIComponent(domain)}&relay_state=${encodeURIComponent(state || clientId)}&redirect=1">前往企业 SAML 登录</a>`;
        return;
      }
      box.textContent = JSON.stringify(data);
      if (data.redirect_url) location.href = data.redirect_url;
    } catch (e) {
      showErr(e.message);
    }
  };

  $("btnPasskeyLogin").onclick = async () => {
    showErr("");
    try {
      const begin = await api("/api/v1/auth/passkey/login/begin", {
        method: "POST",
        body: JSON.stringify({ user_id: "" }),
      });
      const publicKey = begin.publicKey || begin.options || begin;
      const pk = publicKey.publicKey || publicKey;
      pk.challenge = b64urlToBuf(pk.challenge);
      (pk.allowCredentials || []).forEach((c) => { c.id = b64urlToBuf(c.id); });
      const cred = await navigator.credentials.get({ publicKey: pk });
      const body = {
        id: cred.id,
        rawId: bufToB64url(cred.rawId),
        type: cred.type,
        response: {
          clientDataJSON: bufToB64url(cred.response.clientDataJSON),
          authenticatorData: bufToB64url(cred.response.authenticatorData),
          signature: bufToB64url(cred.response.signature),
          userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : null,
        },
      };
      const login = await api("/api/v1/auth/passkey/login/finish", {
        method: "POST",
        headers: { "X-WebAuthn-Session": begin.session_id || "", "X-Device-Id": deviceId },
        body: JSON.stringify(body),
      });
      await finishWithLogin(login);
    } catch (e) {
      showErr(e.message || String(e));
    }
  };

  $("sendOtp").onclick = async () => {
    showErr("");
    try {
      const captcha = $("captchaToken").value || (cfg.captcha_enabled ? prompt("captcha_token（mock 可填任意非 fail）") : "");
      if (cfg.captcha_enabled) $("captchaToken").value = captcha || "";
      await api("/api/v1/auth/challenge", {
        method: "POST",
        body: JSON.stringify({
          method,
          identity: $("identity").value.trim(),
          scene: "login",
          captcha_token: $("captchaToken").value,
        }),
      }).then((data) => {
        $("otp").dataset.challengeId = data.challenge_id;
        alert("验证码已发送：" + (data.masked_target || ""));
      });
    } catch (e) {
      showErr(e.message);
    }
  };

  $("loginForm").onsubmit = async (e) => {
    e.preventDefault();
    showErr("");
    try {
      const credential = {};
      if (method.endsWith("_otp")) {
        credential.challenge_id = $("otp").dataset.challengeId || "";
        credential.otp = $("otp").value.trim();
      } else {
        credential.password = $("password").value;
      }
      const login = await api("/api/v1/auth/login", {
        method: "POST",
        body: JSON.stringify({
          method,
          identity: $("identity").value.trim(),
          credential,
          invite_code: inviteCode || undefined,
          client: { device_id: deviceId, platform: "web", fingerprint: deviceId },
        }),
      });
      await finishWithLogin(login);
    } catch (err) {
      if (err.code === 40120 && err.data && err.data.mfa_token) {
        showMFA(err.data.mfa_token);
        showErr("需要二次验证");
        return;
      }
      showErr(err.message);
    }
  };

  $("mfaForm").onsubmit = async (e) => {
    e.preventDefault();
    showErr("");
    try {
      const login = await api("/api/v1/auth/mfa/complete", {
        method: "POST",
        body: JSON.stringify({
          mfa_token: mfaToken,
          code: $("mfaCode").value.trim(),
          client: { device_id: deviceId, platform: "web", fingerprint: deviceId },
        }),
      });
      await finishWithLogin(login);
    } catch (err) {
      showErr(err.message);
    }
  };

  load().catch((e) => showErr(e.message));
})();
