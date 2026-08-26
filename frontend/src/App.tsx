import { useState, useEffect } from "react";
import { 
  Shield, 
  Activity, 
  List, 
  Menu, 
  X, 
  Settings as SettingsIcon, 
  ChevronRight, 
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
      await apiRequest("/health", { method: "get", timeout: 35000 });
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
      const data = await executeWithRetry(() => apiRequest<StatsData>("/api/stats", { method: "get", timeout: 35000 }), 3, 2000);
      setStats(data);
      setStatsError(null);
      setBackendReady(true);
    } catch (err: any) {
      const msg = parseApiError(err);
      setStatsError(msg);
      setBackendReady(false);
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
      <aside className={`fixed inset-y-0 left-0 z-40 w-64 flex flex-col justify-between transform lg:translate-x-0 lg:static lg:flex transition-transform duration-300 ease-in-out ${sidebarOpen ? "translate-x-0" : "-translate-x-full"}`} style={{ background: "var(--panel)", borderRight: "1px solid var(--border)" }}>
        
        {/* Top Section: Brand + Navigation */}
        <div className="flex flex-col flex-1 min-h-0">
          
          {/* Logo & Header */}
          <div className="h-16 px-5 flex items-center justify-between border-b" style={{ borderColor: "var(--border)" }}>
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg flex items-center justify-center bg-sky-500/10 border border-sky-500/30 text-sky-400 shrink-0">
                <Shield className="w-4 h-4" />
              </div>
              <div>
                <div className="flex items-center gap-1.5">
                  <span className="text-sm font-bold tracking-tight text-white font-mono">FORENSIC AI</span>
                  <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20">v3.0</span>
                </div>
                <p className="text-[10px] text-slate-400 font-mono -mt-0.5">SOC Threat Intel</p>
              </div>
            </div>
            <button
              onClick={() => setSidebarOpen(false)}
              className="lg:hidden p-1.5 rounded-lg border border-white/[0.08] text-slate-400 hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Navigation Items */}
          <div className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
            
            <div className="space-y-1">
              <div className="px-3 pb-2 text-[10px] font-mono font-semibold uppercase tracking-wider text-slate-500">
                Platform Navigation
              </div>
              {navItems.map(item => {
                const Icon = item.icon;
                const active = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => { setActiveTab(item.id); setSidebarOpen(false); }}
                    className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl font-mono text-xs transition text-left ${
                      active
                        ? "bg-sky-500/15 text-sky-400 font-bold border border-sky-500/30 shadow-sm"
                        : "text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] border border-transparent"
                    }`}
                  >
                    <Icon className={`w-4 h-4 shrink-0 ${active ? "text-sky-400" : "text-slate-400"}`} />
                    <div className="flex-1 min-w-0">
                      <p className="leading-none text-xs truncate">{item.label}</p>
                      <p className="text-[10px] text-slate-500 font-normal mt-0.5 truncate">{item.subLabel}</p>
                    </div>
                    {active && <ChevronRight className="w-3.5 h-3.5 text-sky-400/70 shrink-0" />}
                  </button>
                );
              })}
            </div>

            {/* Threat Posture & Status Widget */}
            <div className="px-1 space-y-2">
              <div className="px-2 text-[10px] font-mono font-semibold uppercase tracking-wider text-slate-500">
                System Status
              </div>
              <div className="p-3 rounded-xl border space-y-2 text-xs font-mono" style={{ background: "#0c1018", borderColor: "var(--border)" }}>
                <div className="flex items-center justify-between">
                  <span className="text-[11px] text-slate-400">Threat Posture</span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${
                    threatLevel === "Critical" ? "badge-phishing" : threatLevel === "Elevated" ? "badge-suspicious" : "badge-safe"
                  }`}>
                    {threatLevel}
                  </span>
                </div>
                <div className="flex items-center justify-between text-[11px] pt-1.5 border-t border-white/[0.04]">
                  <span className="text-slate-400">SOC Engine</span>
                  <div className="flex items-center gap-1.5">
                    <div className={`w-1.5 h-1.5 rounded-full ${backendReady ? "bg-emerald-400 animate-pulse" : "bg-amber-400"}`} />
                    <span className={backendReady ? "text-emerald-400" : "text-amber-400"}>
                      {backendReady ? "Operational" : "Connecting..."}
                    </span>
                  </div>
                </div>
              </div>
            </div>

          </div>
        </div>

        {/* Bottom Section: Analyst Profile & Session Footer */}
        <div className="p-3 border-t" style={{ borderColor: "var(--border)", background: "var(--panel)" }}>
          <div className="p-2.5 rounded-xl border border-white/[0.06] bg-black/20 flex items-center justify-between gap-2">
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="w-8 h-8 rounded-lg bg-sky-950/80 border border-sky-500/30 flex items-center justify-center text-sky-400 font-mono font-bold text-xs shrink-0">
                {currentUser?.email ? currentUser.email.charAt(0).toUpperCase() : "A"}
              </div>
              <div className="min-w-0">
                <p className="text-xs font-mono font-bold truncate text-white">
                  {currentUser?.email ? currentUser.email.split('@')[0] : "Guest Analyst"}
                </p>
                <div className="flex items-center gap-1.5">
                  <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${currentUser ? "bg-emerald-400" : "bg-amber-400"}`} />
                  <p className="text-[9px] font-mono text-slate-400 truncate uppercase">
                    {currentUser?.role ? currentUser.role : "Level-1 Clearance"}
                  </p>
                </div>
              </div>
            </div>
            
            <div className="flex items-center gap-1 shrink-0">
              <button
                onClick={() => setOnboardingOpen(true)}
                className="p-1.5 rounded-lg border border-white/[0.08] hover:bg-white/[0.06] text-slate-400 hover:text-sky-300 transition"
                title="Clearance Gateway"
              >
                <Key className="w-3.5 h-3.5" />
              </button>
              {currentUser && (
                <button
                  onClick={handleLogout}
                  className="p-1.5 rounded-lg border border-rose-500/20 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 transition"
                  title="Logout Session"
                >
                  <LogOut className="w-3.5 h-3.5" />
                </button>
              )}
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
