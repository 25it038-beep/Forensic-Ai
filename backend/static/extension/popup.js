(() => {
  const $ = (id) => document.getElementById(id);
  const els = {
    emailText: $("email-text"), urlInput: $("url-input"), scanBtn: $("scan-btn"), clearBtn: $("clear-btn"),
    sourceBadge: $("source-badge"), apiUrlDisplay: $("api-url-display"), apiConfigLink: $("api-config-link"),
    modeText: $("mode-text"), modeUrl: $("mode-url"), modeExtract: $("mode-extract"),
    inputView: $("input-view"), loadingView: $("loading-view"), resultView: $("result-view"),
    resultBanner: $("result-banner"), resultStatus: $("result-status"), resultRisk: $("result-risk"), resultConf: $("result-conf"), resultShield: $("result-shield"), resultExplanation: $("result-explanation"), resultIndicators: $("result-indicators"), resultFlags: $("result-flags"),
    offlineBadge: $("offline-badge"), healthDot: $("health-dot"), settingsBtn: $("settings-btn"),
    historyList: $("history-list"), historyEmpty: $("history-empty"), queueCount: $("queue-count"), footerMode: $("footer-mode"),
    resetBtn: $("reset-btn"), openDashboard: $("open-dashboard"), openOptions: $("open-options"),
    intelContent: $("intel-content"), becBox: $("bec-box"), geoContent: $("geo-content"),
    tabs: Array.from(document.querySelectorAll(".tab")), panels: { verdict: $("tab-verdict"), intel: $("tab-intel"), geo: $("tab-geo") }
  };

  const DEFAULT_API = "https://efinal-vpxh.onrender.com";
  let API_URL = DEFAULT_API;
  let TOKEN = null;
  let currentMode = "text";
  let recentScans = [];
  let offlineQueue = [];

  const STORAGE_KEYS = ["apiUrl","token","recentScans","offlineQueue","sensitivity","badge","notify","inject"];

  function setMode(mode) {
    currentMode = mode;
    [els.modeText, els.modeUrl, els.modeExtract].forEach(b => b && b.classList.remove("active"));
    if (mode === "text") els.modeText.classList.add("active");
    if (mode === "url") els.modeUrl.classList.add("active");
    if (mode === "extract") els.modeExtract.classList.add("active");
    if (mode === "url") {
      els.emailText.style.display = "none"; els.urlInput.style.display = "block"; els.scanBtn.textContent = "ANALYZE URL";
    } else if (mode === "extract") {
      els.emailText.style.display = "block"; els.urlInput.style.display = "none"; els.scanBtn.textContent = "EXTRACT & SCAN";
      triggerExtract();
    } else {
      els.emailText.style.display = "block"; els.urlInput.style.display = "none"; els.scanBtn.textContent = "ANALYZE CONTENT";
    }
  }
  els.modeText.addEventListener("click", () => setMode("text"));
  els.modeUrl.addEventListener("click", () => setMode("url"));
  els.modeExtract.addEventListener("click", () => setMode("extract"));

  function loadConfig() {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get({ apiUrl: DEFAULT_API, token: null, recentScans: [], offlineQueue: [], sensitivity: "balanced" }, (data) => {
        API_URL = (data.apiUrl || DEFAULT_API).replace(/\/$/, "");
        TOKEN = data.token || null;
        recentScans = Array.isArray(data.recentScans) ? data.recentScans : [];
        offlineQueue = Array.isArray(data.offlineQueue) ? data.offlineQueue : [];
        if (els.apiUrlDisplay) els.apiUrlDisplay.textContent = API_URL;
        if (els.footerMode) els.footerMode.textContent = data.sensitivity || "balanced";
        if (els.queueCount) els.queueCount.textContent = String(offlineQueue.length);
        renderHistory();
        checkHealth();
      });
    } else {
      if (els.apiUrlDisplay) els.apiUrlDisplay.textContent = API_URL;
    }
  }

  async function checkHealth() {
    if (!els.healthDot) return;
    els.healthDot.className = "health-dot checking";
    try {
      const r = await fetch(API_URL.replace(/\/$/, "") + "/health", { method: "GET" });
      els.healthDot.className = r.ok ? "health-dot ok" : "health-dot err";
      els.healthDot.title = r.ok ? "Backend online" : `HTTP ${r.status}`;
    } catch {
      els.healthDot.className = "health-dot err";
      els.healthDot.title = "Backend unreachable";
    }
  }

  function renderHistory() {
    if (!els.historyList) return;
    els.historyList.innerHTML = "";
    if (!recentScans.length) {
      els.historyEmpty.style.display = "block";
      return;
    }
    els.historyEmpty.style.display = "none";
    recentScans.slice(0, 6).forEach((item, idx) => {
      const row = document.createElement("div");
      row.className = "history-item";
      const cls = item.classification || item.status || "Safe";
      row.innerHTML = `
        <div style="min-width:0; flex:1">
          <div style="font:700 10px ui-monospace; color:#e2e8f0; white-space:nowrap; overflow:hidden; text-overflow:ellipsis">${(item.subject || item.url || item.textPreview || "Scan").slice(0, 48)}</div>
          <div style="font:9px ui-monospace; color:#64748b">${new Date(item.at || Date.now()).toLocaleTimeString()} · risk ${item.risk_score ?? item.risk ?? "?"}</div>
        </div>
        <span class="cls ${cls}">${cls}</span>
      `;
      row.addEventListener("click", () => {
        if (item.full) displayResults(item.full, !!item.offline);
        else {
          // fallback to text preview
          els.emailText.value = item.textPreview || "";
          setMode("text");
        }
      });
      els.historyList.appendChild(row);
    });
  }

  function saveRecent(entry) {
    recentScans.unshift(entry);
    recentScans = recentScans.slice(0, 10);
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({ recentScans });
    }
    renderHistory();
  }

  function triggerExtract() {
    if (typeof chrome === "undefined" || !chrome.tabs) return;
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];
      if (!tab || !tab.id) return;
      chrome.tabs.sendMessage(tab.id, { action: "getEmailContent" }, (res) => {
        if (chrome.runtime.lastError) return;
        if (res && res.text && res.text.trim().length > 20) {
          els.emailText.value = res.text.trim().slice(0, 8000);
          els.sourceBadge.style.display = "block";
          els.sourceBadge.textContent = `Extracted from ${new URL(res.url || tab.url).hostname} — ${res.text.length} chars`;
          if (els.apiUrlDisplay) els.apiUrlDisplay.textContent = API_URL;
        }
      });
    });
  }

  // Badge / context menu payload
  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(["selectedText", "scanType", "autoScan"], (data) => {
      if (data.selectedText) {
        if (data.scanType === "url") { setMode("url"); els.urlInput.value = data.selectedText; }
        else { setMode("text"); els.emailText.value = data.selectedText; }
        els.sourceBadge.style.display = "block";
        els.sourceBadge.textContent = data.scanType === "url" ? "Link loaded from page" : "Selected text loaded from page";
        try { chrome.action.setBadgeText({ text: "" }); } catch {}
        if (data.autoScan) {
          chrome.storage.local.set({ autoScan: false });
          setTimeout(() => performScan(data.selectedText, data.scanType || "text"), 300);
        }
      }
    });
  }

  // Settings
  if (els.settingsBtn) els.settingsBtn.addEventListener("click", () => {
    if (chrome.runtime && chrome.runtime.openOptionsPage) chrome.runtime.openOptionsPage();
    else window.open("options.html", "_blank");
  });
  if (els.openOptions) els.openOptions.addEventListener("click", (e) => { e.preventDefault(); if (chrome.runtime.openOptionsPage) chrome.runtime.openOptionsPage(); });
  if (els.apiConfigLink) els.apiConfigLink.addEventListener("click", (e) => {
    e.preventDefault();
    const next = prompt("Backend API URL (e.g. https://your-backend.onrender.com) — also set JWT token in Options for private scans", API_URL);
    if (next && next.trim()) {
      API_URL = next.trim().replace(/\/$/, "");
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) chrome.storage.local.set({ apiUrl: API_URL }, () => { if (els.apiUrlDisplay) els.apiUrlDisplay.textContent = API_URL; checkHealth(); });
    }
  });

  // Tabs
  els.tabs.forEach(t => t.addEventListener("click", () => {
    els.tabs.forEach(x => x.classList.remove("active"));
    Object.values(els.panels).forEach(p => p && p.classList.remove("active"));
    t.classList.add("active");
    const id = t.dataset.tab;
    if (els.panels[id]) els.panels[id].classList.add("active");
  }));

  // Actions
  els.scanBtn.addEventListener("click", () => {
    if (currentMode === "url") {
      const url = els.urlInput.value.trim();
      if (!url) return alert("Enter a URL");
      try { new URL(url); } catch { return alert("Invalid URL"); }
      performScan(url, "url");
    } else if (currentMode === "extract") {
      const txt = els.emailText.value.trim();
      if (!txt) return triggerExtract();
      performScan(txt, "text");
    } else {
      const txt = els.emailText.value.trim();
      if (!txt) return alert("Enter text");
      performScan(txt, "text");
    }
  });
  if (els.clearBtn) els.clearBtn.addEventListener("click", () => {
    els.emailText.value = ""; els.urlInput.value = ""; els.sourceBadge.style.display = "none";
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) chrome.storage.local.remove(["selectedText","scanType","autoScan"]);
  });
  if (els.resetBtn) els.resetBtn.addEventListener("click", () => {
    els.resultView.style.display = "none"; els.inputView.style.display = "block";
  });
  if (els.openDashboard) els.openDashboard.addEventListener("click", () => {
    const dashBase = API_URL.replace(/\/api\/?$/, "").replace(/\/$/, "");
    // If backend serves frontend, open backend root; else open stored dashboard URL
    chrome.storage.local.get({ dashboardUrl: "" }, (d) => {
      const url = d.dashboardUrl || dashBase || "http://127.0.0.1:5173";
      chrome.tabs.create({ url });
    });
  });

  // Keyboard shortcut
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "enter") els.scanBtn.click();
  });

  function offlineFallback(text, isUrl) {
    const src = text.toLowerCase();
    // respect sensitivity from storage
    const strict = recentScans && false; // placeholder
    const suspicious = isUrl ? /login|signin|verify|secure|bank|pay|crypto|free/.test(src) : /urgent|verify|login|password|bank|invoice|pay|free|winner/.test(src);
    return {
      classification: suspicious ? "Suspicious" : "Safe",
      risk_score: suspicious ? 68 : 14,
      confidence_score: suspicious ? 71 : 78,
      explanation: suspicious ? "Offline heuristic: phishing cues (urgency / credential request / payment pressure) detected. Backend unreachable — verify via trusted channel." : "Offline heuristic: no obvious phishing cues. Backend unreachable — still verify sender.",
      detected_indicators: {
        urgent_language: /urgent|immediately/i.test(src),
        suspicious_urls: /http|https|login|verify/i.test(src),
        fake_login: /login|signin|verify/i.test(src),
        password_request: /password|reset/i.test(src),
        banking_scam: /bank|invoice/i.test(src),
        financial_fraud: /pay|payment/i.test(src),
        crypto_scam: /crypto|wallet/i.test(src),
        grammar_issues: false, spoofed_sender: false, dangerous_attachments: false
      },
      forensics: { forensic_flags: [], bec_analysis: { is_bec_threat: false } },
      geolocation: null,
      virustotal_results: null, whois_results: null, email_auth_results: { spf: "None", dkim: "None", dmarc: "None", is_authenticated: true }
    };
  }

  async function performScan(text, scanType) {
    els.inputView.style.display = "none";
    els.resultView.style.display = "none";
    els.loadingView.style.display = "block";
    const isUrl = scanType === "url";
    const endpoint = isUrl ? `${API_URL}/api/analyze-url` : `${API_URL}/api/predict`;
    const body = isUrl ? JSON.stringify({ url: text }) : JSON.stringify({ text });
    const headers = { "Content-Type": "application/json" };
    if (TOKEN) headers["Authorization"] = `Bearer ${TOKEN}`;
    // also try to get token from storage if not loaded
    if (!TOKEN && typeof chrome !== "undefined" && chrome.storage) {
      try {
        const data = await new Promise(res => chrome.storage.local.get({ token: null }, res));
        if (data.token) headers["Authorization"] = `Bearer ${data.token}`;
      } catch {}
    }
    try {
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), 11000);
      const res = await fetch(endpoint, { method: "POST", headers, body, signal: controller.signal });
      clearTimeout(t);
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(txt || `HTTP ${res.status}`);
      }
      const data = await res.json();
      let norm;
      if (isUrl) {
        norm = {
          classification: data.status === "Dangerous" ? "Phishing" : data.status,
          risk_score: data.risk_score,
          confidence_score: 92,
          explanation: data.advice,
          detected_indicators: { suspicious_urls: data.status !== "Safe" },
          forensics: data.forensics || {},
          geolocation: data.geolocation,
          virustotal_results: data.virustotal_results,
          whois_results: data.whois_results,
          email_auth_results: null,
          _raw: data
        };
      } else {
        norm = data;
      }
      saveRecent({ textPreview: text.slice(0, 120), classification: norm.classification, risk_score: norm.risk_score, at: Date.now(), full: norm, offline: false, url: isUrl ? text : undefined, subject: norm.subject });
      displayResults(norm, false);
      // badge & notification
      try {
        if (norm.classification === "Phishing") {
          chrome.action.setBadgeText({ text: "!!" }); chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
          chrome.storage.local.get({ notify: true }, (d) => {
            if (d.notify !== false && chrome.notifications) {
              chrome.notifications.create({ type: "basic", iconUrl: "icon.png", title: "Phishing detected", message: `${norm.classification} · risk ${norm.risk_score}/100` });
            }
          });
        } else if (norm.classification === "Suspicious") {
          chrome.action.setBadgeText({ text: "!" }); chrome.action.setBadgeBackgroundColor({ color: "#f59e0b" });
        } else {
          chrome.action.setBadgeText({ text: "✓" }); chrome.action.setBadgeBackgroundColor({ color: "#22c55e" });
          setTimeout(() => chrome.action.setBadgeText({ text: "" }), 3000);
        }
      } catch {}
    } catch (err) {
      console.warn("Backend failed, offline fallback", err);
      const fallback = offlineFallback(text, isUrl);
      fallback._raw = { offline: true, error: String(err).slice(0, 200) };
      saveRecent({ textPreview: text.slice(0, 120), classification: fallback.classification, risk_score: fallback.risk_score, at: Date.now(), full: fallback, offline: true, url: isUrl ? text : undefined });
      // queue for retry
      offlineQueue.unshift({ text, scanType, at: Date.now() });
      offlineQueue = offlineQueue.slice(0, 20);
      if (typeof chrome !== "undefined" && chrome.storage) chrome.storage.local.set({ offlineQueue });
      if (els.queueCount) els.queueCount.textContent = String(offlineQueue.length);
      displayResults(fallback, true);
    }
  }

  function displayResults(data, isOffline) {
    els.loadingView.style.display = "none";
    els.resultView.style.display = "block";
    els.resultStatus.textContent = data.classification.toUpperCase() + (isOffline ? " · OFFLINE" : "");
    els.resultRisk.textContent = Math.round(data.risk_score ?? 0);
    els.resultConf.textContent = data.confidence_score ? `${Math.round(data.confidence_score)}%` : (isOffline ? "heur." : "—");
    els.resultExplanation.textContent = data.explanation || data.advice || "";
    els.resultBanner.className = "result-banner";
    els.offlineBadge.style.display = isOffline ? "inline-block" : "none";
    if (data.classification === "Phishing") { els.resultBanner.classList.add("bg-red"); els.resultShield.textContent = "🚨"; }
    else if (data.classification === "Suspicious") { els.resultBanner.classList.add("bg-yellow"); els.resultShield.textContent = "⚠️"; }
    else { els.resultBanner.classList.add("bg-green"); els.resultShield.textContent = "🛡️"; }

    // Indicators
    els.resultIndicators.innerHTML = "";
    let cnt = 0;
    for (const [k, v] of Object.entries(data.detected_indicators || {})) {
      if (v) {
        cnt++;
        const b = document.createElement("span");
        b.className = "badge badge-red";
        b.textContent = k.replace(/_/g, " ").toUpperCase();
        els.resultIndicators.appendChild(b);
      }
    }
    if (cnt === 0) {
      const b = document.createElement("span");
      b.className = "badge badge-green";
      b.textContent = "NO THREAT INDICATORS";
      els.resultIndicators.appendChild(b);
    }

    // Flags
    els.resultFlags.innerHTML = "";
    const flags = (data.forensics && data.forensics.forensic_flags) || [];
    if (flags.length) {
      const t = document.createElement("div");
      t.className = "section-title";
      t.textContent = "FORENSIC FLAGS";
      els.resultFlags.appendChild(t);
      flags.slice(0, 4).forEach(f => {
        const d = document.createElement("div");
        d.style.cssText = "margin-top:6px; padding:8px 10px; background:rgba(239,68,68,.06); border:1px solid rgba(239,68,68,.18); border-radius:8px; font:10px ui-monospace; color:#fecaca";
        d.textContent = f;
        els.resultFlags.appendChild(d);
      });
    }

    // Intel tab
    if (els.intelContent) {
      els.intelContent.innerHTML = "";
      const vt = data.virustotal_results || data._raw?.virustotal_results;
      const whois = data.whois_results || data._raw?.whois_results;
      const auth = data.email_auth_results;
      const cards = [
        vt ? { k: "VIRUSTOTAL", v: `${vt.malicious} mal / ${vt.harmless} clean` } : null,
        whois ? { k: "WHOIS", v: `${whois.registrar || "Unknown"} · ${whois.domain_age_days ?? "?"}d` } : null,
        auth ? { k: "SPF/DKIM/DMARC", v: `${auth.spf}/${auth.dkim}/${auth.dmarc}` } : null,
        data.bec_analysis || data.forensics?.bec_analysis ? { k: "BEC", v: (data.forensics?.bec_analysis?.bec_type) || "—" } : null,
      ].filter(Boolean);
      if (!cards.length) els.intelContent.innerHTML = '<div class="hint">No live intel (offline or no URL). Connect backend for VT/WHOIS.</div>';
      else cards.forEach(c => {
        const d = document.createElement("div");
        d.className = "intel-card";
        d.innerHTML = `<div class="k">${c.k}</div><div class="v">${c.v}</div>`;
        els.intelContent.appendChild(d);
      });
      // BEC box
      if (els.becBox) {
        els.becBox.innerHTML = "";
        const bec = data.forensics?.bec_analysis || data.bec_analysis;
        if (bec && bec.is_bec_threat) {
          els.becBox.innerHTML = `<div style="padding:10px; background:rgba(239,68,68,.08); border:1px solid rgba(239,68,68,.25); border-radius:8px; font:10px ui-monospace; color:#fecaca"><b>BEC ${bec.bec_type}</b> · ${bec.urgency_level} · ${bec.detected_patterns?.join("; ") || ""}</div>`;
        }
      }
    }

    // Geo tab
    if (els.geoContent) {
      const geo = data.geolocation || data.forensics?.origin_geolocation || data._raw?.geolocation;
      if (geo && geo.country && geo.country !== "Unknown") {
        els.geoContent.innerHTML = `
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px">
            <div class="intel-card"><div class="k">COUNTRY / CITY</div><div class="v">${geo.city || "?"}, ${geo.country}</div></div>
            <div class="intel-card"><div class="k">IP</div><div class="v" style="color:#00f2fe">${geo.ip || "—"}</div></div>
            <div class="intel-card"><div class="k">ISP / ASN</div><div class="v" style="font-size:10px">${geo.isp || geo.asn || "—"}</div></div>
            <div class="intel-card"><div class="k">COORDS</div><div class="v">${geo.latitude?.toFixed ? geo.latitude.toFixed(3) : geo.latitude}, ${geo.longitude?.toFixed ? geo.longitude.toFixed(3) : geo.longitude}</div></div>
          </div>
          <div class="hint" style="margin-top:8px">Source: ${geo.verification_source || "heuristic / live DNS"}</div>
        `;
      } else {
        els.geoContent.innerHTML = '<div class="hint">No verified geolocation (private IP or no URL/email headers). Upload .eml with Received: for hop trace.</div>';
      }
    }

    // Switch to verdict tab
    els.tabs.forEach(x => x.classList.remove("active"));
    Object.values(els.panels).forEach(p => p && p.classList.remove("active"));
    const firstTab = document.querySelector('.tab[data-tab="verdict"]');
    if (firstTab) firstTab.classList.add("active");
    if (els.panels.verdict) els.panels.verdict.classList.add("active");
  }

  loadConfig();
  // also support command
  if (typeof chrome !== "undefined" && chrome.commands) {
    chrome.commands.onCommand.addListener((cmd) => {
      if (cmd === "scan-selection") {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          chrome.tabs.sendMessage(tabs[0].id, { action: "getSelection" }, (res) => {
            if (res && res.text) {
              els.emailText.value = res.text; setMode("text"); performScan(res.text, "text");
            }
          });
        });
      }
    });
  }
})();
