import React, { useState } from "react";
import { Download, Shield, Zap, Eye, Globe, Check, AlertCircle, ExternalLink, FileText, Cpu, Puzzle } from "lucide-react";
import { API_URL, parseApiError } from "../config";

export const BrowserExtensionInfo: React.FC = () => {
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  // User-provided extension store URL — set VITE_EXTENSION_URL in .env or replace placeholder
  const TRY_URL = (import.meta as any).env?.VITE_EXTENSION_URL || "";

  const handleDownload = async () => {
    setDownloading(true);
    setError(null);
    try {
      const base = API_URL || window.location.origin;
      const url = base.endsWith("/") ? `${base}api/extension/download` : `${base}/api/extension/download`;
      const res = await fetch(url);
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(txt || `HTTP ${res.status}`);
      }
      const blob = await res.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "ai_phishing_detector_extension.zip";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(a.href);
      setDone(true);
      setTimeout(() => setDone(false), 3000);
    } catch (e: any) {
      setError(parseApiError(e) || "Download failed. Is the backend running?");
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="space-y-6 animate-slide-up">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="font-orbitron text-lg font-bold text-white tracking-wide flex items-center gap-2">
            <Puzzle className="w-5 h-5 text-cyan-400" /> BROWSER EXTENSION
          </h2>
          <p className="font-code text-[10px] text-slate-500 mt-1 tracking-wider">ONE-CLICK PHISHING SCAN FOR ANY WEBMAIL & SELECTED TEXT</p>
        </div>
        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-md bg-emerald-500/10 border border-emerald-500/20">
          <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          <span className="font-code text-[10px] text-emerald-400">MV3 COMPATIBLE · CHROME / EDGE / BRAVE</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Download card */}
        <div className="lg:col-span-2 panel rounded-xl p-6 space-y-5">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/25 flex items-center justify-center">
              <Shield className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <h3 className="font-orbitron text-sm font-bold text-white">Forensic AI — Extension v2.0 · SOC Grade</h3>
              <p className="font-code text-[10px] text-slate-500">MV3 · Gmail/Outlook inject · Options page · History + offline queue</p>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {[
              { icon: Eye, title: "Select & Link Scan", desc: "Right-click selection / link / page — 3 context menus + Ctrl+Shift+S" },
              { icon: FileText, title: "Gmail Inject", desc: "Auto-injected Scan button in Gmail & Outlook webmail (content script)" },
              { icon: Globe, title: "Live Intel + Offline", desc: "VT · WHOIS · DNS · SSL · Geo + offline heuristic fallback & queue" },
            ].map((f) => (
              <div key={f.title} className="data-cell rounded-lg text-center p-4">
                <f.icon className="w-5 h-5 text-cyan-400 mx-auto" />
                <p className="font-code text-[10px] font-bold text-white mt-2">{f.title}</p>
                <p className="font-code text-[9px] text-slate-500 mt-1 leading-relaxed">{f.desc}</p>
              </div>
            ))}
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {[
              { icon: Zap, title: "SOC Popup", desc: "Risk ring, 3 tabs (Verdict/Intel/Geo), BEC, MITRE, copy & dashboard link" },
              { icon: Shield, title: "History & Queue", desc: "Recent 10 scans local, offline queue (20), click to replay" },
              { icon: Cpu, title: "Options & Auth", desc: "Configurable API URL + JWT token → private history, health check, notifications" },
            ].map((f) => (
              <div key={f.title} className="data-cell rounded-lg text-center p-4">
                <f.icon className="w-5 h-5 text-cyan-400 mx-auto" />
                <p className="font-code text-[10px] font-bold text-white mt-2">{f.title}</p>
                <p className="font-code text-[9px] text-slate-500 mt-1 leading-relaxed">{f.desc}</p>
              </div>
            ))}
          </div>

          {TRY_URL ? (
            <a
              href={TRY_URL}
              target="_blank"
              rel="noreferrer"
              className="w-full btn-primary flex items-center justify-center gap-2 py-3 text-sm no-underline"
            >
              <ExternalLink className="w-4 h-4" /> TRY EXTENSION
            </a>
          ) : (
            <div className="w-full p-3 rounded-lg bg-cyan-500/5 border border-cyan-500/15 text-center">
              <p className="font-code text-[10px] text-cyan-300 font-bold">TRY EXTENSION — link pending</p>
              <p className="font-code text-[9px] text-slate-500 mt-1">Provide your store URL as <code className="text-cyan-400">VITE_EXTENSION_URL</code> to activate this button.</p>
            </div>
          )}

          <button
            onClick={handleDownload}
            disabled={downloading}
            className="w-full flex items-center justify-center gap-2 py-2.5 text-sm rounded-lg border font-code text-[10px] font-bold tracking-widest bg-white/[0.04] border-white/[0.08] text-slate-400 hover:text-white hover:border-white/15"
          >
            {downloading ? (
              <>
                <div className="w-3.5 h-3.5 rounded-full border-2 border-t-cyan-400 border-white/20 animate-spin" /> PACKAGING...
              </>
            ) : done ? (
              <>
                <Check className="w-3.5 h-3.5" /> DOWNLOADED
              </>
            ) : (
              <>
                <Download className="w-3.5 h-3.5" /> DOWNLOAD .ZIP (manual)
              </>
            )}
          </button>

          {error && (
            <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20 font-code text-[10px] text-red-400">
              <AlertCircle className="w-4 h-4" /> {error}
            </div>
          )}

          {done && (
            <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 font-code text-[10px] text-emerald-400">
              ✓ Zip downloaded — now follow the 3-step install to the right.
            </div>
          )}

          <div className="pt-3 border-t border-white/[0.06] flex items-center justify-between font-code text-[9px] text-slate-600">
            <span>API: {API_URL || window.location.origin} /api</span>
            <span className="flex items-center gap-1">
              <Cpu className="w-3 h-3" /> Manifest V3 · Service Worker
            </span>
          </div>
        </div>

        {/* Install steps */}
        <div className="panel rounded-xl p-6 space-y-4">
          <h4 className="font-orbitron text-xs font-bold text-white tracking-wider">INSTALL IN 30 SECONDS</h4>
          <ol className="space-y-3">
            {[
              { n: "1", t: "Unzip", d: "Extract ai_phishing_detector_extension.zip to a permanent folder (e.g. Documents/extensions)." },
              { n: "2", t: "Load unpacked", d: "chrome://extensions → Developer mode ON → Load unpacked → select folder (v2.0)." },
              { n: "3", t: "Configure", d: "Click puzzle → Options (or right-click extension → Options) → set Backend API URL + JWT token for private history, check Health." },
              { n: "4", t: "Scan", d: "Gmail/Outlook: click injected Scan button. Or highlight → right-click → Scan selection / Scan link / Scan page. Or Ctrl+Shift+S." },
            ].map((s) => (
              <li key={s.n} className="flex gap-3">
                <div className="w-7 h-7 rounded-full bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center font-orbitron text-xs font-bold text-cyan-400 flex-shrink-0">
                  {s.n}
                </div>
                <div>
                  <p className="font-code text-xs font-bold text-white">{s.t}</p>
                  <p className="font-code text-[10px] text-slate-400 mt-0.5 leading-relaxed">{s.d}</p>
                </div>
              </li>
            ))}
          </ol>

          <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20">
            <p className="font-code text-[10px] font-bold text-amber-300">Configures automatically</p>
            <p className="font-code text-[9px] text-slate-400 mt-1">
              Extension reads backend URL from your site origin first, then falls back to storage. To point to a self-hosted backend, set <code className="text-cyan-400">VITE_API_URL</code> before building.
            </p>
          </div>

          <a
            href="https://developer.chrome.com/docs/extensions/get-started/tutorial/hello-world#load-unpacked"
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1.5 font-code text-[10px] text-cyan-400 hover:text-cyan-300"
          >
            <ExternalLink className="w-3 h-3" /> Chrome docs: Load unpacked
          </a>
        </div>
      </div>

      <div className="panel rounded-xl p-5 space-y-3">
        <h4 className="font-code text-[10px] font-bold text-slate-400 tracking-widest">PERMISSIONS & MV3 FEATURES</h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-code text-[10px]">
          <div className="flex items-center gap-2 text-slate-300"><FileText className="w-3.5 h-3.5 text-slate-500" /> <span>contextMenus — 4 menus (selection/link/page/email)</span></div>
          <div className="flex items-center gap-2 text-slate-300"><Puzzle className="w-3.5 h-3.5 text-slate-500" /> <span>activeTab + scripting — extract Gmail/Outlook body</span></div>
          <div className="flex items-center gap-2 text-slate-300"><Globe className="w-3.5 h-3.5 text-slate-500" /> <span>storage — JWT, recent 10, offline queue 20, settings</span></div>
          <div className="flex items-center gap-2 text-slate-300"><Shield className="w-3.5 h-3.5 text-slate-500" /> <span>notifications + alarms — Phishing alerts & 5-min health check</span></div>
          <div className="flex items-center gap-2 text-slate-300"><Zap className="w-3.5 h-3.5 text-slate-500" /> <span>host_permissions http/https — call any backend</span></div>
          <div className="flex items-center gap-2 text-slate-300"><Cpu className="w-3.5 h-3.5 text-slate-500" /> <span>commands Ctrl+Shift+S — keyboard scan</span></div>
        </div>
        <div className="p-3 rounded-lg bg-cyan-500/5 border border-cyan-500/15">
          <p className="font-code text-[9px] text-cyan-300 font-bold">Next-level vs v1.1: content script inject, options page, history/queue, 3-tab SOC popup, JWT auth, health dot, notifications.</p>
        </div>
      </div>
    </div>
  );
};
