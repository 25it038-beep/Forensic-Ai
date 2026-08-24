import React, { useEffect, useState } from "react";
import { Monitor, Moon, Sun, Bell, Globe, Database, Trash2, Download, Shield, Save, RotateCcw, Check } from "lucide-react";
import { API_URL } from "../config";

type Theme = "dark" | "light" | "system";
type Density = "comfortable" | "compact";

interface SettingsState {
  theme: Theme;
  density: Density;
  apiUrl: string;
  autoRefresh: boolean;
  notifications: boolean;
  sound: boolean;
  language: string;
}

const STORAGE_KEY = "forensic_settings_v2";

const defaults: SettingsState = {
  theme: "dark",
  density: "comfortable",
  apiUrl: API_URL || "",
  autoRefresh: true,
  notifications: true,
  sound: false,
  language: "en",
};

function load(): SettingsState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) return { ...defaults, ...JSON.parse(raw) };
  } catch {}
  return { ...defaults };
}

function getEffectiveTheme(theme: Theme): "light" | "dark" {
  if (theme === "system") {
    return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  return theme;
}

function applyTheme(theme: Theme) {
  const effective = getEffectiveTheme(theme);
  const root = document.documentElement;
  root.dataset.theme = effective;
  root.style.colorScheme = effective;
  if (effective === "light") root.classList.add("light");
  else root.classList.remove("light");
}

function save(s: SettingsState) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(s));
  applyTheme(s.theme);
  document.documentElement.dataset.density = s.density;
}

export const Settings: React.FC = () => {
  const [state, setState] = useState<SettingsState>(() => load());
  const [health, setHealth] = useState<"idle"|"checking"|"ok"|"fail">("idle");
  const [saved, setSaved] = useState(false);
  const [clearing, setClearing] = useState(false);

  // Apply theme on mount and when system preference changes
  useEffect(() => {
    applyTheme(state.theme);
    document.documentElement.dataset.density = state.density;
    if (state.theme === "system") {
      const mq = window.matchMedia("(prefers-color-scheme: light)");
      const handler = () => applyTheme("system");
      mq.addEventListener("change", handler);
      return () => mq.removeEventListener("change", handler);
    }
  }, []);

  // Persist theme/density instantly (other fields require Save)
  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      const current = raw ? JSON.parse(raw) : {};
      const next = { ...current, theme: state.theme, density: state.density, apiUrl: current.apiUrl ?? state.apiUrl, notifications: current.notifications ?? state.notifications, sound: current.sound ?? state.sound, language: current.language ?? state.language, autoRefresh: current.autoRefresh ?? state.autoRefresh };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {}
    applyTheme(state.theme);
    document.documentElement.dataset.density = state.density;
  }, [state.theme, state.density]);

  const update = (patch: Partial<SettingsState>) => setState(s => ({ ...s, ...patch }));

  const handleSave = () => {
    save(state);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleReset = () => {
    const d = { ...defaults };
    setState(d);
    save(d);
  };

  const checkHealth = async () => {
    setHealth("checking");
    try {
      const base = state.apiUrl || API_URL || window.location.origin;
      const url = base.replace(/\/$/, "") + "/health";
      const r = await fetch(url, { method: "GET" });
      setHealth(r.ok ? "ok" : "fail");
      setTimeout(() => setHealth("idle"), 4000);
    } catch {
      setHealth("fail");
      setTimeout(() => setHealth("idle"), 4000);
    }
  };

  const handleClearHistory = async () => {
    if (!confirm("Clear local scan history and cached telemetry? This does not delete server data.")) return;
    setClearing(true);
    localStorage.removeItem("forensic_recent");
    localStorage.removeItem("forensic_jwt");
    setTimeout(() => setClearing(false), 600);
  };

  const handleExportSettings = () => {
    const blob = new Blob([JSON.stringify(state, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "forensic-settings.json";
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <div className="space-y-6 max-w-[880px] mx-auto">
      {/* Header */}
      <div>
        <h2 className="text-[22px] font-semibold tracking-tight text-white flex items-center gap-2.5">
          <span className="w-8 h-8 rounded-lg bg-white/[0.06] border border-white/[0.08] flex items-center justify-center">
            <Shield className="w-4 h-4 text-slate-300" />
          </span>
          Settings
        </h2>
        <p className="text-[13px] leading-5 text-slate-400 mt-1.5 max-w-[600px]">
          Tailored for SOC analysts — fine-tune appearance, backend connection and data handling. Changes are saved locally and apply instantly.
        </p>
      </div>

      {/* Appearance */}
      <section className="rounded-2xl border border-white/[0.07] bg-white/[0.02] overflow-hidden">
        <div className="px-5 py-4 border-b border-white/[0.06] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Monitor className="w-4 h-4 text-slate-400" />
            <h3 className="text-[13px] font-medium text-white">Appearance</h3>
          </div>
          <span className="text-[11px] text-slate-500 font-mono">UI • Density</span>
        </div>
        <div className="p-5 grid sm:grid-cols-2 gap-5">
          <div>
            <label className="text-[11px] font-medium text-slate-300">Theme</label>
            <div className="mt-2 grid grid-cols-3 gap-2">
              {[
                { id: "dark", label: "Dark", icon: Moon, desc: "SOC default" },
                { id: "light", label: "Light", icon: Sun, desc: "Paper" },
                { id: "system", label: "System", icon: Monitor, desc: "Auto" },
              ].map(opt => {
                const Icon = opt.icon;
                const active = state.theme === opt.id;
                return (
                  <button
                    key={opt.id}
                    onClick={() => update({ theme: opt.id as Theme })}
                    className={`p-3 rounded-xl border text-left transition ${active ? "bg-white text-slate-900 border-white" : "bg-white/[0.03] border-white/[0.07] hover:bg-white/[0.06] hover:border-white/[0.12] text-slate-300"}`}
                  >
                    <Icon className={`w-4 h-4 ${active ? "text-slate-900" : "text-slate-400"}`} />
                    <div className={`text-[12px] font-medium mt-1.5 ${active ? "text-slate-900" : "text-white"}`}>{opt.label}</div>
                    <div className={`text-[11px] ${active ? "text-slate-600" : "text-slate-500"}`}>{opt.desc}</div>
                  </button>
                );
              })}
            </div>
          </div>
          <div>
            <label className="text-[11px] font-medium text-slate-300">Density</label>
            <div className="mt-2 flex gap-2">
              {[
                { id: "comfortable", label: "Comfortable", desc: "Spacious, 16px" },
                { id: "compact", label: "Compact", desc: "Dense, 14px" },
              ].map(opt => (
                <button
                  key={opt.id}
                  onClick={() => update({ density: opt.id as Density })}
                  className={`flex-1 p-3 rounded-xl border text-left ${state.density === opt.id ? "bg-white text-slate-900 border-white" : "bg-white/[0.03] border-white/[0.07] text-slate-300 hover:bg-white/[0.05]"}`}
                >
                  <div className={`text-[12px] font-medium ${state.density===opt.id?"text-slate-900":"text-white"}`}>{opt.label}</div>
                  <div className={`text-[11px] ${state.density===opt.id?"text-slate-600":"text-slate-500"}`}>{opt.desc}</div>
                </button>
              ))}
            </div>
            <p className="text-[11px] text-slate-500 mt-3 leading-relaxed">Compact reduces card padding and chart height — useful on 13″ laptops during triage.</p>
          </div>
        </div>
      </section>

      {/* Backend */}
      <section className="rounded-2xl border border-white/[0.07] bg-white/[0.02] overflow-hidden">
        <div className="px-5 py-4 border-b border-white/[0.06] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Globe className="w-4 h-4 text-slate-400" />
            <h3 className="text-[13px] font-medium text-white">Backend & Network</h3>
          </div>
          <span className={`text-[11px] font-mono px-2 py-1 rounded-full border ${health==="ok"?"bg-emerald-500/10 text-emerald-400 border-emerald-500/20":health==="fail"?"bg-red-500/10 text-red-400 border-red-500/20":"bg-white/[0.04] text-slate-500 border-white/[0.06]"}`}>
            {health==="checking"?"Checking…":health==="ok"?"Online • "+(state.apiUrl||API_URL||window.location.origin):health==="fail"?"Unreachable":"Idle"}
          </span>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="text-[11px] font-medium text-slate-300">API base URL</label>
            <div className="mt-2 flex gap-2">
              <input
                value={state.apiUrl}
                onChange={e => update({ apiUrl: e.target.value })}
                placeholder={API_URL || "http://127.0.0.1:8000  (leave empty for same-origin proxy)"}
                className="flex-1 bg-[#0a0f1a] border border-white/[0.08] rounded-xl px-3.5 py-2.5 text-[13px] text-white placeholder:text-slate-600 focus:outline-none focus:border-white/15 focus:bg-white/[0.04]"
              />
              <button onClick={checkHealth} className="px-3.5 py-2.5 rounded-xl bg-white text-slate-900 text-[12px] font-medium hover:bg-slate-100">Test</button>
            </div>
            <p className="text-[11px] text-slate-500 mt-2 leading-relaxed">
              Leave empty to use Vite proxy (<code className="bg-white/5 border border-white/10 px-1.5 py-0.5 rounded text-[10px]">/api → 127.0.0.1:8000</code>) in dev. For Vercel/Render set <code className="bg-white/5 border border-white/10 px-1 py-0.5 rounded text-[10px]">https://your-backend.onrender.com</code>.
            </p>
          </div>
          <label className="flex items-center justify-between p-3 rounded-xl border border-white/[0.06] bg-white/[0.02] cursor-pointer hover:bg-white/[0.04]">
            <div>
              <div className="text-[12px] font-medium text-white">Auto-refresh telemetry</div>
              <div className="text-[11px] text-slate-500">Poll <code className="bg-white/5 px-1 rounded">/api/stats</code> every 15s</div>
            </div>
            <input type="checkbox" checked={state.autoRefresh} onChange={e => update({ autoRefresh: e.target.checked })} className="w-[18px] h-[18px] accent-white" />
          </label>
        </div>
      </section>

      {/* Notifications & Data */}
      <section className="grid md:grid-cols-2 gap-4">
        <div className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5">
          <div className="flex items-center gap-2.5 mb-4">
            <Bell className="w-4 h-4 text-slate-400" />
            <h3 className="text-[13px] font-medium text-white">Notifications</h3>
          </div>
          <label className="flex items-center justify-between py-2.5">
            <span className="text-[13px] text-slate-300">Desktop toasts</span>
            <input type="checkbox" checked={state.notifications} onChange={e => update({ notifications: e.target.checked })} className="w-[18px] h-[18px] accent-white" />
          </label>
          <label className="flex items-center justify-between py-2.5 border-t border-white/[0.06]">
            <span className="text-[13px] text-slate-300">Sound on Phishing</span>
            <input type="checkbox" checked={state.sound} onChange={e => update({ sound: e.target.checked })} className="w-[18px] h-[18px] accent-white" />
          </label>
          <p className="text-[11px] text-slate-500 mt-3">Sounds are subtle — a single tap, not a siren. Respects OS Do Not Disturb.</p>
        </div>

        <div className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-5">
          <div className="flex items-center gap-2.5 mb-4">
            <Database className="w-4 h-4 text-slate-400" />
            <h3 className="text-[13px] font-medium text-white">Data</h3>
          </div>
          <div className="space-y-2.5">
            <button onClick={handleExportSettings} className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl border border-white/[0.08] bg-white/[0.03] text-[12px] font-medium text-white hover:bg-white/[0.06]">
              <Download className="w-3.5 h-3.5" /> Export settings JSON
            </button>
            <button onClick={handleClearHistory} disabled={clearing} className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl border border-red-500/15 bg-red-500/[0.06] text-[12px] font-medium text-red-300 hover:bg-red-500/10 disabled:opacity-50">
              <Trash2 className="w-3.5 h-3.5" /> {clearing ? "Clearing…" : "Clear local cache"}
            </button>
          </div>
          <p className="text-[11px] text-slate-500 mt-3">Clears JWT and recent scans from this browser only. Server history stays intact.</p>
        </div>
      </section>

      {/* Footer actions */}
      <div className="flex items-center justify-between pt-2">
        <div className="text-[11px] text-slate-500">
          <span className="inline-flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-emerald-500" /> Forensic AI v3.0</span>
          <span className="mx-2 text-white/10">·</span>
          <span>Security Operations Console</span>
        </div>
        <div className="flex gap-2">
          <button onClick={handleReset} className="px-3.5 py-2 rounded-xl border border-white/[0.08] bg-white/[0.04] text-[12px] font-medium text-slate-300 hover:bg-white/[0.07] flex items-center gap-1.5">
            <RotateCcw className="w-3.5 h-3.5" /> Reset
          </button>
          <button onClick={handleSave} className="px-4 py-2 rounded-xl bg-white text-slate-900 text-[12px] font-medium hover:bg-slate-100 flex items-center gap-1.5">
            {saved ? <><Check className="w-3.5 h-3.5" /> Saved</> : <><Save className="w-3.5 h-3.5" /> Save</>}
          </button>
        </div>
      </div>
    </div>
  );
};
