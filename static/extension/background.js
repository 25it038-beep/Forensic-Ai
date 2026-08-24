const DEFAULT_API = "https://efinal-vpxh.onrender.com";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: "scanPhishing", title: "Scan selection for Phishing", contexts: ["selection"] });
    chrome.contextMenus.create({ id: "scanLink", title: "Scan link URL for Phishing", contexts: ["link"] });
    chrome.contextMenus.create({ id: "scanPage", title: "Scan this page URL (SOC)", contexts: ["page"] });
    chrome.contextMenus.create({ id: "scanEmail", title: "Extract & scan visible email", contexts: ["page"], documentUrlPatterns: ["https://mail.google.com/*", "https://outlook.live.com/*", "https://outlook.office.com/*"] });
  });
  chrome.storage.local.get({ apiUrl: DEFAULT_API, recentScans: [], offlineQueue: [], notify: true, badge: true }, (d) => {
    if (!d.apiUrl) chrome.storage.local.set({ apiUrl: DEFAULT_API });
  });
  // health alarm every 5 min
  try { chrome.alarms.create("healthCheck", { periodInMinutes: 5 }); } catch {}
  // quick health probe
  probeHealth();
});

async function probeHealth() {
  try {
    const { apiUrl } = await chrome.storage.local.get({ apiUrl: DEFAULT_API });
    const u = (apiUrl || DEFAULT_API).replace(/\/$/, "") + "/health";
    const r = await fetch(u);
    if (r.ok) {
      chrome.action.setBadgeText({ text: "" });
      // optional: set icon
    } else {
      chrome.action.setBadgeText({ text: "!" });
      chrome.action.setBadgeBackgroundColor({ color: "#f59e0b" });
    }
  } catch {
    // offline
  }
}

try {
  chrome.alarms.onAlarm.addListener((a) => { if (a.name === "healthCheck") probeHealth(); });
} catch {}

chrome.contextMenus.onClicked.addListener((info, tab) => {
  let payload = null;
  if (info.menuItemId === "scanPhishing" && info.selectionText) {
    payload = { selectedText: info.selectionText, scanType: "text", autoScan: true };
  } else if (info.menuItemId === "scanLink" && info.linkUrl) {
    payload = { selectedText: info.linkUrl, scanType: "url", autoScan: true };
  } else if (info.menuItemId === "scanPage" && tab && tab.url) {
    payload = { selectedText: tab.url, scanType: "url", autoScan: true };
  } else if (info.menuItemId === "scanEmail" && tab && tab.id) {
    // ask content script to extract email
    chrome.tabs.sendMessage(tab.id, { action: "getEmailContent" }, (res) => {
      if (chrome.runtime.lastError) return;
      if (res && res.text) {
        chrome.storage.local.set({ selectedText: res.text, scanType: "text", autoScan: true }, () => {
          chrome.action.setBadgeText({ text: "SCAN" });
          chrome.action.setBadgeBackgroundColor({ color: "#00f2fe" });
          if (chrome.notifications) chrome.notifications.create({ type: "basic", iconUrl: "icon.png", title: "Email extracted", message: `Queued ${res.text.length} chars — open popup to analyze` });
        });
      }
    });
    return;
  }
  if (payload) {
    chrome.storage.local.set(payload, () => {
      chrome.storage.local.get({ badge: true }, (d) => {
        if (d.badge !== false) {
          chrome.action.setBadgeText({ text: "SCAN" });
          chrome.action.setBadgeBackgroundColor({ color: "#00f2fe" });
        }
      });
      chrome.storage.local.get({ notify: true }, (d) => {
        if (d.notify !== false && chrome.notifications) {
          chrome.notifications.create({ type: "basic", iconUrl: "icon.png", title: "Forensic AI queued", message: `${payload.scanType === "url" ? "URL" : "Text"} queued — click shield to analyze` });
        }
      });
    });
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.action) return;
  if (msg.action === "getTabUrl") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      sendResponse({ url: tabs[0] ? tabs[0].url : "" });
    });
    return true;
  }
  if (msg.action === "contentScan") {
    chrome.storage.local.get({ badge: true }, (d) => {
      if (d.badge !== false) {
        chrome.action.setBadgeText({ text: "SCAN" });
        chrome.action.setBadgeBackgroundColor({ color: "#00f2fe" });
      }
    });
  }
  if (msg.action === "scanResult") {
    // popup can send scan result to background to handle badge/notification centrally
    const data = msg.data;
    if (data && data.classification === "Phishing") {
      chrome.action.setBadgeText({ text: "!!" });
      chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
    } else if (data && data.classification === "Suspicious") {
      chrome.action.setBadgeText({ text: "!" });
      chrome.action.setBadgeBackgroundColor({ color: "#f59e0b" });
    }
  }
});

chrome.commands.onCommand.addListener((command) => {
  if (command === "scan-selection") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];
      if (!tab || !tab.id) return;
      chrome.tabs.sendMessage(tab.id, { action: "getSelection" }, (res) => {
        if (chrome.runtime.lastError) {
          // fallback to scripting
          chrome.scripting.executeScript({ target: { tabId: tab.id }, func: () => window.getSelection()?.toString() || "" }, (results) => {
            const txt = results && results[0] && results[0].result;
            if (txt) chrome.storage.local.set({ selectedText: txt, scanType: "text", autoScan: true });
          });
          return;
        }
        if (res && res.text) chrome.storage.local.set({ selectedText: res.text, scanType: "text", autoScan: true });
      });
    });
  }
});

// Keep service worker alive for alarms (MV3)
chrome.runtime.onStartup.addListener(() => probeHealth());
