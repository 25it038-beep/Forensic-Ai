const $ = (id) => document.getElementById(id);
const els = { apiUrl: $("apiUrl"), token: $("token"), badge: $("badge"), notify: $("notify"), inject: $("inject"), sensitivity: $("sensitivity"), status: $("status"), health: $("health") };
const DEFAULTS = { apiUrl: "https://efinal-vpxh.onrender.com", token: "", badge: true, notify: true, inject: true, sensitivity: "balanced" };

function setStatus(msg, ok = true) {
  els.status.textContent = msg;
  els.status.className = ok ? "ok" : "err";
  if (ok) setTimeout(() => (els.status.textContent = ""), 2500);
}

async function checkHealth(url) {
  els.health.textContent = "Health: checking…";
  els.health.className = "hint muted";
  try {
    const u = url.replace(/\/$/, "") + "/health";
    const r = await fetch(u, { method: "GET" });
    if (r.ok) {
      const j = await r.json().catch(() => ({}));
      els.health.textContent = `Health: ${j.status || "ok"} ✓ at ${new URL(url).host}`;
      els.health.className = "hint ok";
    } else {
      els.health.textContent = `Health: HTTP ${r.status} at ${new URL(url).host}`;
      els.health.className = "hint err";
    }
  } catch (e) {
    els.health.textContent = `Health: unreachable — ${e.message || "network error"}`;
    els.health.className = "hint err";
  }
}

function load() {
  chrome.storage.local.get(DEFAULTS, (data) => {
    els.apiUrl.value = data.apiUrl || DEFAULTS.apiUrl;
    if (els.token) els.token.value = data.token || "";
    els.badge.checked = data.badge !== false;
    els.notify.checked = data.notify !== false;
    els.inject.checked = data.inject !== false;
    els.sensitivity.value = data.sensitivity || "balanced";
    checkHealth(els.apiUrl.value);
  });
}

$("save").addEventListener("click", () => {
  let apiUrl = els.apiUrl.value.trim().replace(/\/$/, "");
  try {
    const u = new URL(apiUrl);
    if (!/^https?:$/.test(u.protocol)) throw new Error("Use http/https");
  } catch (e) {
    setStatus("Invalid API URL: " + e.message, false);
    return;
  }
  const token = els.token ? els.token.value.trim() : "";
  if (token && token.split(".").length !== 3) {
    setStatus("Token looks invalid (expected JWT with 3 parts)", false);
    return;
  }
  chrome.storage.local.set(
    {
      apiUrl,
      token,
      badge: els.badge.checked,
      notify: els.notify.checked,
      inject: els.inject.checked,
      sensitivity: els.sensitivity.value,
    },
    () => {
      setStatus("Saved ✓");
      checkHealth(apiUrl);
    }
  );
});

$("reset").addEventListener("click", () => {
  chrome.storage.local.set(DEFAULTS, () => {
    load();
    setStatus("Reset to defaults");
  });
});

els.apiUrl.addEventListener("change", () => checkHealth(els.apiUrl.value));
$("openPopup").addEventListener("click", (e) => {
  e.preventDefault();
  if (chrome.action && chrome.action.openPopup) chrome.action.openPopup();
  else alert("Open the extension popup via the toolbar shield icon.");
});

load();
