(() => {
  const BADGE_ID = "forensic-ai-inject-btn";
  const SELECTOR_GMAIL_SUBJECT = "h2.hP";
  const SELECTOR_GMAIL_SENDER = ".gD";
  const SELECTOR_GMAIL_BODY = ".a3s.aiL";
  const SELECTOR_OUTLOOK_SUBJECT = "[data-testid='conversationSubject'], div[role='heading']";
  const SELECTOR_OUTLOOK_BODY = "div[role='document'] div[dir='ltr'], div.ReadMsgBody";

  function getGmailEmail() {
    const subj = document.querySelector(SELECTOR_GMAIL_SUBJECT);
    const sender = document.querySelector(SELECTOR_GMAIL_SENDER);
    const bodyEl = document.querySelector(SELECTOR_GMAIL_BODY);
    if (!subj && !bodyEl) return null;
    const textParts = [];
    if (subj) textParts.push(`Subject: ${subj.innerText.trim()}`);
    if (sender) textParts.push(`From: ${sender.getAttribute("email") || sender.innerText.trim()}`);
    if (bodyEl) textParts.push(bodyEl.innerText.trim().slice(0, 8000));
    const t = textParts.join("\n\n");
    return t.length > 20 ? t : null;
  }

  function getOutlookEmail() {
    const subj = document.querySelector(SELECTOR_OUTLOOK_SUBJECT);
    const bodyEl = document.querySelector(SELECTOR_OUTLOOK_BODY);
    if (!subj && !bodyEl) return null;
    const parts = [];
    if (subj) parts.push(`Subject: ${subj.innerText.trim()}`);
    if (bodyEl) parts.push(bodyEl.innerText.trim().slice(0, 8000));
    const t = parts.join("\n\n");
    return t.length > 20 ? t : null;
  }

  function getCurrentEmailText() {
    return getGmailEmail() || getOutlookEmail() || window.getSelection()?.toString()?.trim() || document.body.innerText.slice(0, 5000);
  }

  function injectButton() {
    if (document.getElementById(BADGE_ID)) return;
    // Find a stable anchor: Gmail toolbar, Outlook header
    const anchors = [
      document.querySelector("div.ha"), // gmail top
      document.querySelector("div[role='main'] h2"),
      document.querySelector("[data-testid='messageHeader']"),
      document.querySelector("div[aria-label='Message header']")
    ].filter(Boolean);
    const anchor = anchors[0];
    if (!anchor) return;

    const btn = document.createElement("button");
    btn.id = BADGE_ID;
    btn.textContent = "🛡️ Scan with Forensic AI";
    btn.title = "Send visible email to Forensic AI SOC (local or cloud)";
    btn.style.cssText = [
      "margin:8px 0",
      "padding:7px 12px",
      "background:linear-gradient(90deg,#00f2fe,#4facfe)",
      "border:none",
      "border-radius:999px",
      "color:#001018",
      "font:700 11px/1 system-ui,sans-serif",
      "letter-spacing:.04em",
      "cursor:pointer",
      "box-shadow:0 2px 10px rgba(0,242,254,.35)",
      "z-index:9999"
    ].join(";");
    btn.addEventListener("click", () => {
      const txt = getCurrentEmailText();
      if (!txt || txt.length < 10) { alert("No email content found to scan."); return; }
      chrome.storage.local.set({ selectedText: txt, scanType: "text", autoScan: true }, () => {
        // ping background to badge, then open popup hint
        chrome.runtime.sendMessage({ action: "contentScan", length: txt.length });
        btn.textContent = "✓ Queued — open extension popup";
        setTimeout(() => (btn.textContent = "🛡️ Scan with Forensic AI"), 2500);
      });
    });
    anchor.insertAdjacentElement("afterend", btn);
  }

  // MutationObserver for SPA
  const obs = new MutationObserver(() => {
    try { injectButton(); } catch {}
  });
  obs.observe(document.documentElement, { childList: true, subtree: true });
  // Initial
  setTimeout(injectButton, 1200);
  setInterval(injectButton, 4000);

  // Message handler for popup
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg && msg.action === "getEmailContent") {
      const txt = getCurrentEmailText();
      sendResponse({ text: txt || "", url: location.href });
      return true;
    }
    if (msg && msg.action === "getSelection") {
      sendResponse({ text: window.getSelection()?.toString() || "" });
      return true;
    }
  });
})();
