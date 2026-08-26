import React from 'react';
import { Shield, AlertTriangle, Activity, Lock, Database, Brain, Globe, ArrowUpRight, ArrowDownRight, Play, ExternalLink, FileSearch } from 'lucide-react';
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
  stats: StatsData | null; loading?: boolean; error?: string | null;
  onRefresh?: () => void; onSelectScan: (s: PredictResponse) => void;
  onLaunchAnalysis?: () => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ stats, onSelectScan, onLaunchAnalysis }) => {
  const safeStats: StatsData = stats || {
    total_scans: 0,
    safe_count: 0,
    suspicious_count: 0,
    phishing_count: 0,
    average_confidence: 0,
    risk_distribution: { "0-20": 0, "21-40": 0, "41-60": 0, "61-80": 0, "81-100": 0 },
    daily_scans: [],
    weekly_scans: [],
    most_impersonated_brands: [],
    top_phishing_keywords: [],
    most_dangerous_domains: [],
    country_distribution: {},
    file_type_distribution: {},
    recent_scans: []
  };

  const avgConf = safeStats.average_confidence ? `${safeStats.average_confidence.toFixed(1)}%` : "100%";

  const kpis = [
    {
      title: "Emails Analyzed",
      value: safeStats.total_scans,
      label: "Total telemetry ingress",
      icon: Activity,
      trend: "+12% this week",
      trendUp: true,
      color: "text-sky-400",
      badgeColor: "bg-sky-500/10 text-sky-400 border-sky-500/20"
    },
    {
      title: "Threats Detected",
      value: safeStats.phishing_count + safeStats.suspicious_count,
      label: "Neutralized vectors",
      icon: Shield,
      trend: safeStats.phishing_count > 0 ? "Critical active" : "Zero active",
      trendUp: safeStats.phishing_count === 0,
      color: "text-rose-400",
      badgeColor: "bg-rose-500/10 text-rose-400 border-rose-500/20"
    },
    {
      title: "Phishing Attempts",
      value: safeStats.phishing_count,
      label: "Confirmed attacks",
      icon: AlertTriangle,
      trend: "Quarantined",
      trendUp: true,
      color: "text-rose-400",
      badgeColor: "bg-rose-500/10 text-rose-400 border-rose-500/20"
    },
    {
      title: "Suspicious Origin IPs",
      value: (safeStats.top_origin_asns?.length || Object.keys(safeStats.country_distribution || {}).length || 0),
      label: "Anomalous relays",
      icon: Globe,
      trend: "Monitored",
      trendUp: true,
      color: "text-amber-400",
      badgeColor: "bg-amber-500/10 text-amber-400 border-amber-500/20"
    },
    {
      title: "Malicious Domains",
      value: (safeStats.most_dangerous_domains?.length || 0),
      label: "Typosquatting & VT flags",
      icon: Database,
      trend: "Blocklisted",
      trendUp: true,
      color: "text-cyan-400",
      badgeColor: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
    },
    {
      title: "High-Confidence Triage",
      value: avgConf,
      label: "Calibrated model accuracy",
      icon: Brain,
      trend: "Multi-vector ML",
      trendUp: true,
      color: "text-emerald-400",
      badgeColor: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
    },
  ];

  return (
    <div className="space-y-6 max-w-[1400px] mx-auto animate-fade-in">
      
      {/* ── HEADER BANNER ── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b" style={{ borderColor: "var(--border)" }}>
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-[11px] font-mono font-semibold tracking-wider text-sky-400 uppercase">
              SECURITY OPERATIONS CENTER • COMMAND TELEMETRY
            </span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white mt-1">Operational Threat Overview</h1>
          <p className="text-xs text-slate-400 mt-0.5 max-w-2xl">
            Real-time RFC 5322 header forensics, dual-node server routing inspection, and calibrated Machine Learning triage.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => onLaunchAnalysis?.()}
            className="px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs flex items-center gap-2 transition shadow-sm"
          >
            <Play className="w-3.5 h-3.5" />
            <span>Launch Investigation</span>
          </button>
        </div>
      </div>

      {/* ── 6 TOP SOC KPI CARDS ── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-3.5">
        {kpis.map((kpi) => {
          const Icon = kpi.icon;
          return (
            <div
              key={kpi.title}
              className="soc-card p-4 flex flex-col justify-between space-y-3"
            >
              <div className="flex items-start justify-between">
                <span className="text-[11px] font-medium text-slate-400 tracking-wide">{kpi.title}</span>
                <div className={`w-7 h-7 rounded-md flex items-center justify-center border ${kpi.badgeColor}`}>
                  <Icon className="w-3.5 h-3.5" />
                </div>
              </div>
              <div>
                <div className={`text-2xl font-bold font-mono tracking-tight text-white`}>
                  {kpi.value}
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5 truncate">{kpi.label}</div>
              </div>
              <div className="pt-2 border-t flex items-center justify-between text-[10px] font-mono" style={{ borderColor: "var(--border)" }}>
                <span className="text-slate-400">{kpi.trend}</span>
                {kpi.trendUp ? (
                  <ArrowUpRight className="w-3 h-3 text-emerald-400" />
                ) : (
                  <ArrowDownRight className="w-3 h-3 text-rose-400" />
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* ── MAIN CHARTS & THREAT MATRIX ── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        
        {/* Activity Trend Chart */}
        <div className="lg:col-span-8 soc-card p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b" style={{ borderColor: "var(--border)" }}>
            <div>
              <h3 className="text-sm font-semibold text-white">Daily Investigation Ingress</h3>
              <p className="text-[11px] text-slate-400 mt-0.5">Forensic volume processed over recent tracking periods</p>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20">
                Live Ingestion
              </span>
            </div>
          </div>
          <div className="h-60 w-full pt-2">
            {safeStats.daily_scans.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={safeStats.daily_scans}>
                  <defs>
                    <linearGradient id="scanGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#0284c7" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#0284c7" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="date" stroke="#64748b" fontSize={10} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                  <Tooltip contentStyle={{ background: "#0f172a", borderColor: "#334155", borderRadius: "8px", fontSize: "11px", color: "#fff" }} />
                  <Area type="monotone" dataKey="count" stroke="#38bdf8" strokeWidth={2} fillOpacity={1} fill="url(#scanGrad)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-center p-6 text-slate-500 font-mono text-xs">
                <FileSearch className="w-8 h-8 text-slate-600 mb-2" />
                <span>No historical ingress logged yet.</span>
                <span className="text-[10px] text-slate-600 mt-1">Run an investigation in Threat Analyzer to generate telemetry.</span>
              </div>
            )}
          </div>
        </div>

        {/* Threat Severity Distribution */}
        <div className="lg:col-span-4 soc-card p-5 space-y-4">
          <div className="pb-3 border-b" style={{ borderColor: "var(--border)" }}>
            <h3 className="text-sm font-semibold text-white">Threat Severity Matrix</h3>
            <p className="text-[11px] text-slate-400 mt-0.5">Risk score breakdown across all investigations</p>
          </div>
          <div className="space-y-3 pt-1">
            {[
              { label: "Critical (81-100)", count: safeStats.risk_distribution["81-100"] || 0, color: "bg-rose-500" },
              { label: "High (61-80)", count: safeStats.risk_distribution["61-80"] || 0, color: "bg-amber-500" },
              { label: "Medium (41-60)", count: safeStats.risk_distribution["41-60"] || 0, color: "bg-yellow-500" },
              { label: "Low (21-40)", count: safeStats.risk_distribution["21-40"] || 0, color: "bg-sky-500" },
              { label: "Nominal / Safe (0-20)", count: safeStats.risk_distribution["0-20"] || 0, color: "bg-emerald-500" },
            ].map((r) => {
              const pct = safeStats.total_scans > 0 ? (r.count / safeStats.total_scans) * 100 : 0;
              return (
                <div key={r.label} className="space-y-1">
                  <div className="flex justify-between text-[11px] font-mono">
                    <span className="text-slate-400">{r.label}</span>
                    <span className="font-bold text-white">{r.count} ({pct.toFixed(0)}%)</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                    <div className={`h-full ${r.color}`} style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

      </div>

      {/* ── RECENT INCIDENT INVESTIGATIONS TABLE ── */}
      <div className="soc-card p-5 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b" style={{ borderColor: "var(--border)" }}>
          <div>
            <h3 className="text-sm font-semibold text-white">Recent Forensic Incidents</h3>
            <p className="text-[11px] text-slate-400 mt-0.5">Verified evidence dossiers triaged by the forensic engine</p>
          </div>
          <button
            onClick={() => onLaunchAnalysis?.()}
            className="text-xs font-mono text-sky-400 hover:text-sky-300 flex items-center gap-1 transition"
          >
            <span>New Investigation</span>
            <ExternalLink className="w-3 h-3" />
          </button>
        </div>

        <div>
          {safeStats.recent_scans && safeStats.recent_scans.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b text-slate-400 font-mono text-[10px] uppercase" style={{ borderColor: "var(--border)" }}>
                    <th className="pb-2 font-medium">Incident Target</th>
                    <th className="pb-2 font-medium">Origin / Sender</th>
                    <th className="pb-2 font-medium">Timestamp</th>
                    <th className="pb-2 font-medium text-right">Verdict & Risk</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.04]">
                  {safeStats.recent_scans.map((scan, i) => (
                    <tr
                      key={scan.id || i}
                      onClick={() => onSelectScan(scan)}
                      className="hover:bg-white/[0.02] cursor-pointer transition"
                    >
                      <td className="py-2.5 pr-4 font-medium text-white max-w-[280px] truncate">
                        {scan.subject || "Direct RFC 5322 Ingestion"}
                      </td>
                      <td className="py-2.5 pr-4 font-mono text-slate-400 max-w-[200px] truncate text-[11px]">
                        {scan.sender || "Unknown Ingestion"}
                      </td>
                      <td className="py-2.5 pr-4 font-mono text-slate-500 text-[10px]">
                        {scan.created_at ? new Date(scan.created_at).toLocaleString() : "Live"}
                      </td>
                      <td className="py-2.5 text-right">
                        <span className={`text-[10px] font-mono px-2.5 py-0.5 rounded-full border font-bold ${
                          scan.classification === "Phishing" ? "badge-phishing" :
                          scan.classification === "Suspicious" ? "badge-suspicious" :
                          "badge-safe"
                        }`}>
                          {scan.classification.toUpperCase()} • {scan.risk_score.toFixed(0)}/100
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="py-8 text-center text-xs text-slate-500 font-mono">
              No recent investigations logged. Select Threat Analyzer to inspect emails or URLs.
            </div>
          )}
        </div>
      </div>

      <div className="flex items-center gap-2 text-[11px] pt-1 text-slate-500 font-mono">
        <Lock className="w-3 h-3" /> NIST SP 800-86 & ISO/IEC 27037 Standard Compliant Telemetry
      </div>
    </div>
  );
};

