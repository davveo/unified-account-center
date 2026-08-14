(() => {
  const $ = (id) => document.getElementById(id);
  const out = $("out");
  async function api(path, opts = {}) {
    const headers = Object.assign({
      "Content-Type": "application/json",
      "X-Client-Id": $("clientId").value.trim(),
      Authorization: "Bearer " + $("token").value.trim().replace(/^Bearer\s+/i, ""),
    }, opts.headers || {});
    const res = await fetch(path, { ...opts, headers });
    const body = await res.json().catch(() => ({}));
    if (!res.ok || (body.code && body.code !== 0)) {
      throw new Error(body.message || res.statusText || "request failed");
    }
    return body.data;
  }
  function show(data) { out.textContent = JSON.stringify(data, null, 2); }
  $("btnMe").onclick = async () => { try { show(await api("/api/v1/auth/me")); } catch (e) { out.textContent = e.message; } };
  $("btnSessions").onclick = async () => { try { show(await api("/api/v1/auth/sessions")); } catch (e) { out.textContent = e.message; } };
  $("btnMFA").onclick = async () => { try { show(await api("/api/v1/auth/mfa/status")); } catch (e) { out.textContent = e.message; } };
  $("btnRevokeOthers").onclick = async () => {
    try { show(await api("/api/v1/auth/sessions/revoke-others", { method: "POST", body: "{}" })); }
    catch (e) { out.textContent = e.message; }
  };
})();
