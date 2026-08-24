import { useState, useEffect } from "react";
import { 
  Shield, 
  Activity, 
  List, 
  Menu, 
  X, 
  Settings as SettingsIcon, 
  ChevronRight, 
  Radio, 
  Lock, 
  Users, 
  RefreshCw, 
  LogOut,
  Key
} from "lucide-react";
import { Dashboard } from "./components/Dashboard";
import { EmailAnalyzer } from "./components/EmailAnalyzer";
import { History } from "./components/History";
import { Auth } from "./components/Auth";
import { Settings } from "./components/Settings";
import { ChatPanel } from "./components/ChatPanel";
import { SocOnboarding } from "./components/SocOnboarding";
import { parseApiError, executeWithRetry, apiRequest } from "./config";

interface StatsData {
  total_scans: number; safe_count: number; suspicious_count: number;
  phishing_count: number; average_confidence: number;
  risk_distribution: Record<string, number>;
  daily_scans: { date: string; count: number }[];
  weekly_scans: { date: string; count: number }[];
  most_impersonated_brands: { brand: string; count: number }[];
  top_phishing_keywords: { word: string; count: number }[];
  most_dangerous_domains: { domain: string; risk: number }[];
  country_distribution: Record<string, number>;
  file_type_distribution: Record<string, number>;
  top_origin_asns?: { asn: string; count: number }[];
  header_spoofing_rate?: number;
  recent_scans: any[];
}

export default function App() {
  const [activeTab, setActiveTab] = useState<"dashboard"|"analyzer"|"history"|"auth"|"settings">("dashboard");
  const [stats, setStats]         = useState<StatsData | null>(null);
  const [loadingStats, setLoadingStats] = useState(false);
  const [statsError, setStatsError] = useState<string | null>(null);
  const [sidebarOpen, setSidebarOpen]   = useState(false);
  const [triggerRefresh, setTriggerRefresh] = useState(false);
  const [toast, setToast] = useState<{ message: string; type: "success"|"error"|"info" } | null>(null);
  const [time, setTime]   = useState(new Date());
  const [backendReady, setBackendReady] = useState<boolean | null>(null);

  // SOC Clearance Onboarding State
  const [onboardingOpen, setOnboardingOpen] = useState<boolean>(() => {
    const hasToken = localStorage.getItem("forensic_jwt");
    const dismissed = localStorage.getItem("soc_onboarding_dismissed");
    return !hasToken && !dismissed;
  });
  const [currentUser, setCurrentUser] = useState<any>(null);

  const fetchCurrentUser = async () => {
    const t = localStorage.getItem("forensic_jwt");
    if (!t) {
      setCurrentUser(null);
      return;
    }
    try {
      const me = await apiRequest<any>("/api/auth/me", {
        headers: { Authorization: `Bearer ${t}` } as any
      });
      setCurrentUser(me);
    } catch {
      localStorage.removeItem("forensic_jwt");
      setCurrentUser(null);
    }
  };

  useEffect(() => {
    fetchCurrentUser();
  }, []);

  // Theme + density init — respects forensic_settings_v2 and system preference
  useEffect(() => {
    const apply = () => {
      try {
        const raw = localStorage.getItem("forensic_settings_v2");
        const data = raw ? JSON.parse(raw) : {};
        const theme = data.theme || "dark";
        const density = data.density || "comfortable";
        const eff = theme === "system" ? (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark") : theme;
        document.documentElement.dataset.theme = eff;
        document.documentElement.dataset.density = density;
        document.documentElement.style.colorScheme = eff;
        if (eff === "light") document.documentElement.classList.add("light");
        else document.documentElement.classList.remove("light");
      } catch {}
    };
    apply();
    const mq = window.matchMedia("(prefers-color-scheme: light)");
    const onChange = () => {
      try {
        const raw = localStorage.getItem("forensic_settings_v2");
        const t = raw ? JSON.parse(raw).theme : "dark";
        if (t === "system") apply();
      } catch {}
    };
    mq.addEventListener("change", onChange);
    window.addEventListener("storage", apply);
    const id = setInterval(apply, 1000);
    return () => { mq.removeEventListener("change", onChange); window.removeEventListener("storage", apply); clearInterval(id); };
  }, []);

  useEffect(() => { const t = setInterval(() => setTime(new Date()), 1000); return () => clearInterval(t); }, []);

  const showToast = (message: string, type: "success"|"error"|"info" = "success") => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  const checkHealth = async () => {
    try {
      await apiRequest("/health", { method: "get", timeout: 8000 });
      setBackendReady(true);
      return true;
    } catch {
      setBackendReady(false);
      return false;
    }
  };

  const fetchStats = async () => {
    setLoadingStats(true);
    setStatsError(null);
    try {
      await executeWithRetry(() => apiRequest("/health", { method: "get", timeout: 8000 }), 3, 1500);
      setBackendReady(true);
      const data = await executeWithRetry(() => apiRequest<StatsData>("/api/stats", { method: "get", timeout: 15000 }), 4, 1500);
      setStats(data);
      setStatsError(null);
      setBackendReady(true);
    } catch (err: any) {
      const msg = parseApiError(err);
      setStatsError(msg);
      setBackendReady(false);
      if (stats) showToast(msg, "error");
    } finally {
      setLoadingStats(false);
    }
  };

  useEffect(() => { fetchStats(); }, []);

  useEffect(() => {
    if (statsError && !loadingStats) {
      const t = setTimeout(() => fetchStats(), 3000);
      return () => clearTimeout(t);
    }
  }, [statsError, loadingStats]);

  useEffect(() => { checkHealth(); const id = setInterval(checkHealth, 15000); return () => clearInterval(id); }, []);

  const handleRefreshAll = () => {
    fetchStats(); fetchCurrentUser(); setTriggerRefresh(p => !p); showToast("Telemetry refreshed", "info");
  };

  const handleLogout = () => {
    localStorage.removeItem("forensic_jwt");
    setCurrentUser(null);
    showToast("Logged out of SOC session", "info");
    fetchStats();
  };

  const navItems = [
    { id: "dashboard", label: "SOC Dashboard",  subLabel: "Telemetry Overview",  icon: Activity },
    { id: "analyzer",  label: "Threat Analyzer", subLabel: "Scan & Investigate",  icon: Shield   },
    { id: "history",   label: "Incident Log",    subLabel: "Forensic Records",    icon: List     },
    { id: "auth",      label: "SOC Clearance",   subLabel: currentUser ? "Operator Active" : "Login / Onboard", icon: Users },
    { id: "settings",  label: "Settings",        subLabel: "Preferences & API",   icon: SettingsIcon },
  ] as const;

  const threatLevel =
    stats ? (stats.phishing_count  > 0 ? "Critical"
           : stats.suspicious_count > 0 ? "Elevated" : "Nominal")
           : "Standby";

  // If Onboarding Portal is open, display full-screen gateway
  if (onboardingOpen) {
    return (
      <SocOnboarding 
        onComplete={(user) => {
          setCurrentUser(user);
          setOnboardingOpen(false);
          localStorage.setItem("soc_onboarding_dismissed", "true");
          showToast(`Welcome, ${user?.email || "Analyst"}. Clearance Granted.`, "success");
          fetchStats();
        }}
        onSkip={() => {
          setOnboardingOpen(false);
          localStorage.setItem("soc_onboarding_dismissed", "true");
          showToast("Guest Operator Clearance active", "info");
        }}
      />
    );
  }

  return (
    <div className="flex min-h-screen" style={{ background: "var(--bg)", color: "var(--text)" }}>

      {toast && (
        <div className={`fixed bottom-5 right-5 z-50 px-4 py-3 rounded-lg flex items-center gap-3
          font-code text-xs animate-slide-up
          ${toast.type === "error" ? "panel-red text-red-400"
            : toast.type === "info" ? "panel-cyan text-cyan-400"
            : "panel-green text-emerald-400"}`}
          style={{ minWidth: 260 }}>
          <div className={`w-2 h-2 rounded-full flex-shrink-0 animate-pulse
            ${toast.type === "error" ? "bg-red-400" : toast.type === "info" ? "bg-cyan-400" : "bg-emerald-400"}`} />
          <span>{toast.message}</span>
        </div>
      )}

      {sidebarOpen && (
        <div className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm lg:hidden"
          onClick={() => setSidebarOpen(false)} />
      )}

      {/* SIDEBAR */}
      <aside className={`fixed inset-y-0 left-0 z-40 w-72 flex flex-col transform lg:translate-x-0 lg:static lg:flex transition-transform duration-300 ease-in-out ${sidebarOpen ? "translate-x-0" : "-translate-x-full"}`} style={{ background: "var(--panel)", borderRight: "1px solid var(--border)" }}>

        <div className="px-5 py-4 border-b" style={{ borderColor: "var(--border)" }}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <Shield className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-[15px] font-bold tracking-tight font-mono" style={{ color: "var(--text)" }}>SOC FORENSICS</h1>
                <p className="text-[10px] font-mono -mt-0.5" style={{ color: "var(--muted)" }}>Neural Telemetry • v3.0</p>
              </div>
            </div>
            <button onClick={() => setSidebarOpen(false)}
              className="lg:hidden p-1.5 rounded-md border text-slate-500" style={{ background: "var(--panel-soft)", borderColor: "var(--border)" }}>
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* THREAT POSTURE HUD */}
        <div className="mx-4 mt-4 p-3 rounded-xl flex items-center gap-3" style={{ background: "var(--panel)", border: "1px solid var(--border)", borderLeft: `3px solid ${threatLevel==="Critical"?"#ef4444":threatLevel==="Elevated"?"#f59e0b":threatLevel==="Nominal"?"#10b981":"#e5e7eb"}` }}>
          <Radio className="w-4 h-4 flex-shrink-0" style={{ color: threatLevel==="Critical"?"#ef4444":threatLevel==="Elevated"?"#f59e0b":threatLevel==="Nominal"?"#10b981":"#9ca3af" }} />
          <div className="flex-grow">
            <p className="text-[10px] font-medium tracking-wide font-mono" style={{ color: "var(--muted)" }}>THREAT POSTURE</p>
            <p className="text-[12px] font-bold font-mono -mt-0.5" style={{ color: "var(--text)" }}>{threatLevel}</p>
          </div>
          <div className="w-2 h-2 rounded-full" style={{ background: threatLevel==="Critical"?"#ef4444":threatLevel==="Elevated"?"#f59e0b":threatLevel==="Nominal"?"#10b981":"#9ca3af" }} />
        </div>

        {/* OPERATOR CLEARANCE BADGE */}
        <div className="mx-4 mt-2 p-2.5 rounded-xl border border-white/[0.06] bg-black/30 flex items-center justify-between">
          <div className="flex items-center gap-2 min-w-0">
            <div className={`w-2 h-2 rounded-full flex-shrink-0 ${currentUser ? "bg-emerald-400 animate-pulse" : "bg-amber-400"}`} />
            <div className="min-w-0">
              <p className="text-[10px] font-mono font-bold truncate text-white">
                {currentUser?.email ? currentUser.email : "Guest Analyst"}
              </p>
              <p className="text-[8px] font-mono text-slate-500 uppercase">
                {currentUser?.role ? currentUser.role : "Level-1 Clearance"}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setOnboardingOpen(true)}
              className="p-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] text-slate-400 hover:text-cyan-300 font-mono text-[9px] border border-white/[0.05]"
              title="Open SOC Onboarding & Clearance Gateway"
            >
              <Key className="w-3.5 h-3.5" />
            </button>
            {currentUser && (
              <button
                onClick={handleLogout}
                className="p-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 font-mono text-[9px] border border-red-500/20"
                title="Logout of SOC Session"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>

        <nav className="flex-grow p-4 space-y-1 mt-2">
          {navItems.map(item => {
            const Icon = item.icon;
            const active = activeTab === item.id;
            return (
              <button key={item.id}
                onClick={() => { setActiveTab(item.id); setSidebarOpen(false); }}
                className={`nav-item ${active ? "nav-item-active" : "nav-item-inactive"}`}>
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 border ${active ? "bg-slate-900 text-white border-slate-900" : "bg-transparent text-slate-500 border-transparent"}`} style={active ? {} : { background: "var(--panel-soft)", borderColor: "var(--border)" }}>
                  <Icon className="w-4 h-4" />
                </div>
                <div className="flex-grow min-w-0 text-left">
                  <p className="text-[13px] font-medium leading-none" style={{ color: active ? "var(--text)" : "var(--muted)" }}>{item.label}</p>
                  <p className="text-[11px] mt-0.5 font-normal" style={{ color: "var(--faint)" }}>{item.subLabel}</p>
                </div>
                {active && <ChevronRight className="w-3.5 h-3.5 flex-shrink-0" style={{ color: "var(--faint)" }} />}
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t" style={{ borderColor: "var(--border)" }}>
          <div className="rounded-xl p-3 space-y-2.5" style={{ background: "var(--panel-soft)", border: "1px solid var(--border)" }}>
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-medium font-mono" style={{ color: "var(--muted)" }}>SOC Telemetry</span>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${backendReady === false ? "bg-amber-50 text-amber-700 border-amber-200" : backendReady ? "bg-emerald-50 text-emerald-700 border-emerald-200" : "bg-slate-100 text-slate-600 border-slate-200"}`}>
                {backendReady === false ? "Connecting…" : backendReady ? "Operational" : "Checking…"}
              </span>
            </div>
            <div className="grid grid-cols-2 gap-2 text-[11px]">
              {[
                ["Neural ML", backendReady ? "Calibrated" : "—"],
                ["Forensics", "RFC 5322"],
                ["Geolocation", "Dual-Node"],
                ["Sovereign", "NIC/GOV"],
              ].map(([k,v]) => (
                <div key={k} className="flex items-center justify-between">
                  <span style={{ color: "var(--faint)" }}>{k}</span>
                  <span className="font-medium font-mono text-[10px]" style={{ color: "var(--text-soft)" }}>{v}</span>
                </div>
              ))}
            </div>
            <div className="flex items-center gap-1.5 pt-2.5 border-t" style={{ borderColor: "var(--border)" }}>
              <Lock className="w-3 h-3" style={{ color: "var(--faint)" }} />
              <span className="text-[10px] font-mono" style={{ color: "var(--faint)" }}>AES-256 GCM Encrypted</span>
            </div>
          </div>
        </div>
      </aside>

      {/* MAIN CONTENT */}
      <div className="flex-grow flex flex-col min-w-0 min-h-screen">

        <header className="h-[56px] px-5 flex items-center justify-between sticky top-0 z-30" style={{ background: "var(--bg)", borderBottom: "1px solid var(--border)" }}>
          <div className="flex items-center gap-3">
            <button onClick={() => setSidebarOpen(true)}
              className="lg:hidden p-2 rounded-lg border" style={{ background: "var(--panel)", borderColor: "var(--border)", color: "var(--muted)" }}>
              <Menu className="w-4 h-4" />
            </button>
            <div>
              <h2 className="text-[14px] font-semibold tracking-tight leading-none" style={{ color: "var(--text)" }}>{navItems.find(n=>n.id===activeTab)?.label}</h2>
              <p className="text-[12px] hidden sm:block leading-none mt-0.5" style={{ color: "var(--muted)" }}>{navItems.find(n=>n.id===activeTab)?.subLabel}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            
            {/* SOC ONBOARDING / CLEARANCE GATEWAY BUTTON */}
            <button
              onClick={() => setOnboardingOpen(true)}
              className="px-3 py-1.5 rounded-full border border-cyan-500/30 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 font-mono text-[11px] flex items-center gap-1.5 transition-all shadow-[0_0_12px_rgba(0,240,255,0.15)]"
              title="Open Security Clearance Gateway"
            >
              <Key className="w-3 h-3 text-cyan-400" />
              <span className="hidden sm:inline font-bold">SOC CLEARANCE</span>
            </button>

            <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-full border text-[12px]" style={{ background: "var(--panel)", borderColor: "var(--border)", color: "var(--muted)" }}>
              <span className="tabular-nums font-medium font-mono" style={{ color: "var(--text-soft)" }}>{time.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded-full" style={{ background: "var(--panel-soft)", color: "var(--faint)" }}>IST</span>
            </div>

            {stats && (
              <div className="hidden lg:flex items-center gap-3 text-[12px] border rounded-full px-3 py-1.5" style={{ background: "var(--panel)", borderColor: "var(--border)" }}>
                <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-emerald-500" /> <span style={{ color: "var(--text-soft)" }}>{stats.safe_count} safe</span></span>
                <span className="w-px h-3" style={{ background: "var(--border)" }} />
                <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-red-500" /> <span style={{ color: "var(--text-soft)" }}>{stats.phishing_count} threats</span></span>
              </div>
            )}

            <button onClick={handleRefreshAll} className="p-2 rounded-lg border" style={{ background: "var(--panel)", borderColor: "var(--border)", color: "var(--muted)" }} title="Refresh telemetry">
              <RefreshCw className="w-4 h-4" />
            </button>
            <button onClick={() => setActiveTab("settings")} className="p-2 rounded-lg border" style={{ background: activeTab==="settings" ? "var(--text)" : "var(--panel)", color: activeTab==="settings" ? "var(--bg)" : "var(--muted)", borderColor: "var(--border)" }} title="Settings">
              <SettingsIcon className="w-4 h-4" />
            </button>
          </div>
        </header>

        <main className="flex-grow p-5 md:p-7 max-w-screen-2xl mx-auto w-full">
          {statsError && !stats && (
            <div className="mb-4 p-4 rounded-xl bg-amber-500/10 border border-amber-500/20 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <div className="w-2 h-2 rounded-full bg-amber-400 animate-pulse flex-shrink-0" />
                <div>
                  <p className="font-code text-[11px] font-bold text-amber-300">Backend waking…</p>
                  <p className="font-code text-[9px] text-slate-400 mt-0.5 max-w-[520px] truncate">{statsError}</p>
                  <p className="font-code text-[9px] text-slate-500 mt-1">Auto-retrying every 3s · Cold start on Render can take 20–40s</p>
                </div>
              </div>
              <button onClick={fetchStats} className="px-4 py-2 rounded-lg bg-amber-500/15 border border-amber-500/30 font-code text-[10px] font-bold text-amber-300 hover:bg-amber-500/20 flex items-center gap-2 flex-shrink-0">
                <RefreshCw className="w-3.5 h-3.5" /> RETRY NOW
              </button>
            </div>
          )}
          {activeTab === "dashboard" && (
            <Dashboard stats={stats} loading={loadingStats} error={statsError} onRefresh={handleRefreshAll} onSelectScan={() => setActiveTab("history")} onLaunchAnalysis={() => setActiveTab("analyzer")} />
          )}
          {activeTab === "analyzer" && (
            <EmailAnalyzer onScanCompleted={fetchStats} />
          )}
          {activeTab === "history" && (
            <History triggerRefresh={triggerRefresh} onScanSelected={() => {}} />
          )}
          {activeTab === "auth" && (
            <Auth onAuthChange={() => { fetchStats(); fetchCurrentUser(); }} />
          )}
          {activeTab === "settings" && (
            <Settings />
          )}
        </main>
      </div>
      <ChatPanel />
    </div>
  );
}
