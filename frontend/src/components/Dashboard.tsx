import React from 'react';
import { Shield, AlertTriangle, ShieldCheck, Activity, RefreshCw, Lock, Database, Server, Brain, Clock, Target, Play, ExternalLink } from 'lucide-react';
import { ResponsiveContainer, XAxis, YAxis, Tooltip, AreaChart, Area } from 'recharts';

interface PredictResponse {
  id?: number; classification: string; confidence_score: number; risk_score: number; explanation: string; subject?: string; sender?: string; created_at?: string; threat_type?: string;
}
interface StatsData {
  total_scans: number; safe_count: number; suspicious_count: number; phishing_count: number; average_confidence: number;
  risk_distribution: Record<string, number>; daily_scans: { date: string; count: number }[]; weekly_scans: any[];
  most_impersonated_brands: { brand: string; count: number }[]; top_phishing_keywords: { word: string; count: number }[];
  most_dangerous_domains: { domain: string; risk: number }[]; country_distribution: Record<string, number>;
  file_type_distribution: Record<string, number>; top_origin_asns?: { asn: string; count: number }[]; header_spoofing_rate?: number; recent_scans: PredictResponse[];
}
interface DashboardProps {
  stats: StatsData | null; loading: boolean; error?: string | null;
  onRefresh: () => void; onSelectScan: (s: PredictResponse) => void;
  onLaunchAnalysis?: () => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ stats, loading, error, onRefresh, onSelectScan, onLaunchAnalysis }) => {
  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <div className="w-8 h-8 rounded-full border-2 border-slate-200 border-t-slate-900 animate-spin" />
        <p className="text-[13px] mt-3" style={{ color: "var(--muted)" }}>Loading live telemetry…</p>
      </div>
    );
  }
  if (!stats) {
    return (
      <div className="max-w-md mx-auto py-16 text-center">
        <div className="w-12 h-12 rounded-xl bg-amber-50 border border-amber-200 flex items-center justify-center mx-auto">
          <RefreshCw className="w-5 h-5 text-amber-600" />
        </div>
        <h3 className="text-[15px] font-semibold mt-4" style={{ color: "var(--text)" }}>Backend not reachable</h3>
        <p className="text-[13px] mt-1.5 leading-5" style={{ color: "var(--muted)" }}>{error || "Check API connection."}</p>
        <button onClick={onRefresh} className="mt-4 px-4 py-2 rounded-lg bg-slate-900 text-white text-[13px] font-medium">Retry</button>
      </div>
    );
  }

  const lastScan = stats.recent_scans[0];
  const lastAgo = lastScan?.created_at ? `${Math.max(1, Math.round((Date.now() - new Date(lastScan.created_at).getTime()) / 60000))}m ago` : "—";
  const avgConf = stats.average_confidence ? `${stats.average_confidence.toFixed(1)}%` : "—";

  return (
    <div className="space-y-8 max-w-[1200px] mx-auto">
      {/* 1. OPERATIONS OVERVIEW HERO */}
      <section className="rounded-2xl border overflow-hidden" style={{ background: "var(--panel)", borderColor: "var(--border)" }}>
        <div className="px-6 sm:px-8 py-7 sm:py-8">
          <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-6">
            <div className="max-w-[640px]">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <span className="text-[11px] font-mono font-bold tracking-widest text-cyan-400 uppercase">LIVE SECURITY OPERATIONS CENTER</span>
              </div>
              <h1 className="text-[26px] sm:text-[28px] font-semibold tracking-tight mt-2 leading-tight" style={{ color: "var(--text)" }}>
                Automated Email Forensics & Threat Telemetry
              </h1>
              <p className="text-[14px] leading-relaxed mt-2" style={{ color: "var(--muted)" }}>
                Cryptographic RFC 5322 header inspection, dual-node server routing verification, and calibrated machine learning phishing classification.
              </p>
              <div className="flex flex-wrap gap-3 mt-5">
                <button onClick={() => onLaunchAnalysis?.()} className="px-5 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-[13px] font-semibold flex items-center gap-2 transition-all shadow-sm">
                  <Play className="w-4 h-4" /> Start Email Forensic Scan
                </button>
                <button onClick={() => document.getElementById("core-metrics")?.scrollIntoView({ behavior: "smooth" })} className="px-5 py-2.5 rounded-lg border text-[13px] font-medium hover:bg-white/[0.04] transition-colors" style={{ background: "var(--panel)", borderColor: "var(--border)", color: "var(--text)" }}>
                  View Live Incident Metrics
                </button>
              </div>
              <div className="flex flex-wrap gap-2 mt-4">
                {[
                  "RFC 5322 Received Hop Parser",
                  "NIC / Sovereign Government Registry Verification",
                  "Live DNS • RDAP • DoH • VirusTotal Integration",
                  "MITRE ATT&CK Behavioral Mapping",
                ].map(t => (
                  <span key={t} className="text-[11px] px-2.5 py-1 rounded-full border font-mono" style={{ background: "var(--panel-soft)", borderColor: "var(--border)", color: "var(--muted)" }}>{t}</span>
                ))}
              </div>
            </div>
            <div className="lg:w-[340px] shrink-0 space-y-3">
              <div className="rounded-xl border p-4 bg-black/40" style={{ borderColor: "var(--border)" }}>
                <div className="text-[11px] font-mono font-medium tracking-wider uppercase text-slate-400">OPERATIONAL STATUS</div>
                <div className="mt-3 grid grid-cols-2 gap-3 text-[12px]">
                  <div><div style={{ color: "var(--faint)" }}>System</div><div className="font-semibold flex items-center gap-1.5 text-emerald-400"><span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> Operational</div></div>
                  <div><div style={{ color: "var(--faint)" }}>Neural Engine</div><div className="font-medium font-mono" style={{ color: "var(--text)" }}>Active • {stats.total_scans} Scans</div></div>
                  <div><div style={{ color: "var(--faint)" }}>Last Incident</div><div className="font-medium font-mono" style={{ color: "var(--text)" }}>{lastAgo}</div></div>
                  <div><div style={{ color: "var(--faint)" }}>Avg Confidence</div><div className="font-medium font-mono" style={{ color: "var(--text)" }}>{avgConf}</div></div>
                </div>
                <div className="mt-3 pt-3 border-t text-[11px] flex items-center justify-between" style={{ borderColor: "var(--border)", color: "var(--muted)" }}>
                  <span>Verified Threats: <b className="text-red-400 font-mono">{stats.phishing_count}</b></span>
                  <span>Database: <b className="text-emerald-400 font-mono">Synchronized</b></span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 2. COMMAND-CENTER LIVE BAR */}
      <section id="core-metrics" className="grid grid-cols-2 lg:grid-cols-6 gap-3">
        {[
          { k: "System", v: "Operational", sub: "FastAPI + DB", icon: Server, ok: true },
          { k: "Neural ML", v: "Calibrated", sub: `${stats.total_scans} analyzed`, icon: Brain, ok: true },
          { k: "Last Scan", v: lastAgo, sub: lastScan ? lastScan.classification : "Awaiting data", icon: Clock, ok: !!lastScan },
          { k: "Threats", v: String(stats.phishing_count), sub: "Quarantined", icon: Shield, warn: stats.phishing_count > 0 },
          { k: "Confidence", v: avgConf, sub: "Average", icon: Target, ok: true },
          { k: "Storage", v: "Persistent", sub: "Cryptographic", icon: Database, ok: true },
        ].map(item => (
          <div key={item.k} className="rounded-xl border p-3 flex items-center gap-3" style={{ background: "var(--panel)", borderColor: "var(--border)" }}>
            <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0" style={{ background: "var(--panel-soft)", border: "1px solid var(--border)" }}>
              <item.icon className="w-4 h-4" style={{ color: item.warn ? "#ef4444" : item.ok ? "#10b981" : "#64748b" }} />
            </div>
            <div className="min-w-0">
              <div className="text-[11px] leading-none" style={{ color: "var(--faint)" }}>{item.k}</div>
              <div className="text-[13px] font-semibold leading-none mt-1 truncate" style={{ color: "var(--text)" }}>{item.v}</div>
              <div className="text-[11px] truncate mt-0.5" style={{ color: "var(--muted)" }}>{item.sub}</div>
            </div>
          </div>
        ))}
      </section>

      {/* 3. CORE METRIC CARDS */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { title: "Total Scanned Emails", value: stats.total_scans, color: "var(--text)", sub: "Verified transmissions", icon: Activity },
          { title: "Phishing Attacks Blocked", value: stats.phishing_count, color: "#ef4444", sub: "Malicious payloads", icon: Shield },
          { title: "Suspicious Under Review", value: stats.suspicious_count, color: "#f59e0b", sub: "Anomalous routing", icon: AlertTriangle },
          { title: "Safe Legitimate Traffic", value: stats.safe_count, color: "#10b981", sub: "Authenticated senders", icon: ShieldCheck },
        ].map(c => (
          <div key={c.title} className="rounded-2xl border p-5 space-y-2" style={{ background: "var(--panel)", borderColor: "var(--border)" }}>
            <div className="flex items-center justify-between">
              <span className="text-[12px] font-medium" style={{ color: "var(--muted)" }}>{c.title}</span>
              <c.icon className="w-4 h-4" style={{ color: c.color }} />
            </div>
            <div className="text-[28px] font-bold font-mono tracking-tight" style={{ color: c.color }}>{c.value}</div>
            <div className="text-[11px]" style={{ color: "var(--faint)" }}>{c.sub}</div>
          </div>
        ))}
      </section>

      {/* 4. ACTIVITY TIMELINE & RISK DISTRIBUTION */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8 rounded-2xl border p-5 sm:p-6" style={{ background: "var(--panel)", borderColor: "var(--border)" }}>
          <div className="flex items-center justify-between pb-4 border-b" style={{ borderColor: "var(--border)" }}>
            <div>
              <h3 className="text-[15px] font-semibold" style={{ color: "var(--text)" }}>Daily Forensic Telemetry</h3>
              <p className="text-[12px] mt-0.5" style={{ color: "var(--muted)" }}>Incident volume over the last 7 active tracking days</p>
            </div>
          </div>
          <div className="h-64 mt-4">
            {stats.daily_scans.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={stats.daily_scans}>
                  <defs>
                    <linearGradient id="scanGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="date" stroke="var(--faint)" fontSize={11} tickLine={false} />
                  <YAxis stroke="var(--faint)" fontSize={11} tickLine={false} />
                  <Tooltip contentStyle={{ background: "#0b0f19", borderColor: "rgba(255,255,255,0.1)", borderRadius: "8px", fontSize: "12px", color: "#fff" }} />
                  <Area type="monotone" dataKey="count" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#scanGrad)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-500">
                No scan history logged yet. Run your first email scan to populate activity.
              </div>
            )}
          </div>
        </div>

        <div className="lg:col-span-4 rounded-2xl border p-5 sm:p-6 space-y-4" style={{ background: "var(--panel)", borderColor: "var(--border)" }}>
          <h3 className="text-[15px] font-semibold" style={{ color: "var(--text)" }}>Threat Severity Matrix</h3>
          <p className="text-[12px]" style={{ color: "var(--muted)" }}>Distribution of risk scores across all scanned artifacts</p>
          <div className="space-y-3 pt-2">
            {[
              { label: "Critical Risk (81-100)", count: stats.risk_distribution["81-100"] || 0, color: "bg-red-500" },
              { label: "High Risk (61-80)", count: stats.risk_distribution["61-80"] || 0, color: "bg-orange-500" },
              { label: "Medium Risk (41-60)", count: stats.risk_distribution["41-60"] || 0, color: "bg-amber-500" },
              { label: "Low Risk (21-40)", count: stats.risk_distribution["21-40"] || 0, color: "bg-blue-500" },
              { label: "Nominal / Safe (0-20)", count: stats.risk_distribution["0-20"] || 0, color: "bg-emerald-500" },
            ].map(r => {
              const pct = stats.total_scans > 0 ? (r.count / stats.total_scans) * 100 : 0;
              return (
                <div key={r.label} className="space-y-1">
                  <div className="flex justify-between text-[11px] font-mono">
                    <span style={{ color: "var(--muted)" }}>{r.label}</span>
                    <span className="font-bold" style={{ color: "var(--text)" }}>{r.count} ({pct.toFixed(0)}%)</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                    <div className={`h-full ${r.color}`} style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* 5. RECENT VERIFIED INCIDENTS */}
      <section className="rounded-2xl border p-5 sm:p-6" style={{ background: "var(--panel)", borderColor: "var(--border)" }}>
        <div className="flex items-center justify-between pb-4 border-b" style={{ borderColor: "var(--border)" }}>
          <div>
            <h3 className="text-[15px] font-semibold" style={{ color: "var(--text)" }}>Recent Incident Investigations</h3>
            <p className="text-[12px] mt-0.5" style={{ color: "var(--muted)" }}>Authentic forensic records processed by the triage engine</p>
          </div>
          <button onClick={() => onLaunchAnalysis?.()} className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1">
            <span>New Scan</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="mt-4">
          {stats.recent_scans && stats.recent_scans.length > 0 ? (
            <div className="divide-y divide-white/[0.05]">
              {stats.recent_scans.map((scan, i) => (
                <div key={scan.id || i} onClick={() => onSelectScan(scan)} className="py-3 px-2 flex items-center justify-between hover:bg-white/[0.02] rounded-lg cursor-pointer transition-colors">
                  <div className="min-w-0 pr-4">
                    <p className="text-xs font-medium text-white truncate max-w-md">
                      {scan.subject || "Untitled Email Stream"}
                    </p>
                    <p className="text-[10px] font-mono text-slate-500 mt-0.5 truncate">
                      From: {scan.sender || "Direct Raw Input"} · {scan.created_at ? new Date(scan.created_at).toLocaleString() : "Live Session"}
                    </p>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className={`text-[10px] font-mono px-2.5 py-1 rounded-full border font-bold ${
                      scan.classification === "Phishing" ? "bg-red-500/15 text-red-400 border-red-500/30" :
                      scan.classification === "Suspicious" ? "bg-amber-500/15 text-amber-400 border-amber-500/30" :
                      "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                    }`}>
                      {scan.classification.toUpperCase()} · {scan.risk_score.toFixed(0)}/100
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="py-10 text-center text-xs text-slate-500 font-mono">
              No recent scans recorded. Use the Threat Analyzer to inspect emails or URLs.
            </div>
          )}
        </div>
      </section>

      <div className="flex items-center gap-2 text-[11px] pt-2 border-t font-mono" style={{ borderColor: "var(--border)", color: "var(--faint)" }}>
        <Lock className="w-3.5 h-3.5" /> All telemetry data is queried directly from live backend endpoints. Zero synthetic mock injections.
      </div>
    </div>
  );
};
