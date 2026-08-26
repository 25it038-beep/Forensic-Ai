import React, { useState } from "react";
import {
  ShieldCheck,
  Lock,
  ArrowRight,
  Eye,
  EyeOff,
  Mail,
  KeyRound,
  Server,
  MapPin,
  Sparkles,
  ChevronRight,
  Loader2,
} from "lucide-react";
import { apiRequest, parseApiError } from "../config";

interface SocOnboardingProps {
  onComplete: (user?: any) => void;
  onSkip: () => void;
}

const CAPABILITIES = [
  {
    title: "Dual-Node Geolocation",
    desc: "Correlates claimed sender identity against physical relay server hardware on an interactive map.",
    icon: MapPin,
    color: "text-purple-400 bg-purple-500/10 border-purple-500/20 group-hover:border-purple-500/40",
  },
  {
    title: "Zero Synthetic Telemetry",
    desc: "Strictly verifies RFC 5322 transit headers and official government sovereign registries.",
    icon: Server,
    color: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20 group-hover:border-cyan-500/40",
  },
  {
    title: "Explainable AI & MITRE ATT&CK",
    desc: "Clear risk scoring with social engineering technique attribution and tamper-proof forensic dossiers.",
    icon: Sparkles,
    color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20 group-hover:border-emerald-500/40",
  },
] as const;

const TAGS = [
  "RFC 5322 Header Parsing",
  "Live DNS & RDAP",
  "MITRE ATT&CK Mapping",
  "Forensic Dossiers",
];

export const SocOnboarding: React.FC<SocOnboardingProps> = ({ onComplete, onSkip }) => {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("SOC Analyst");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const tokenKey = "forensic_jwt";

  const handleGuestAccess = () => {
    localStorage.setItem("soc_analyst_guest", "true");
    onSkip();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (mode === "register") {
        await apiRequest("/api/auth/register", {
          method: "post",
          data: { email: email.trim(), password },
        });
      }

      const data: any = await apiRequest("/api/auth/login", {
        method: "post",
        data: { email: email.trim(), password },
      });

      localStorage.setItem(tokenKey, data.access_token);
      localStorage.removeItem("soc_analyst_guest");
      onComplete(data.user);
    } catch (err: any) {
      setError(parseApiError(err));
    } finally {
      setLoading(false);
    }
  };

  const inputClass =
    "w-full pl-10 pr-3.5 py-3 bg-slate-900/60 border border-slate-700/60 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/70 focus:ring-2 focus:ring-cyan-500/20 transition-all duration-200";

  return (
    <div className="relative min-h-screen w-full flex items-center justify-center p-4 sm:p-6 lg:p-12 bg-[#090d16] text-slate-100 font-sans selection:bg-cyan-500 selection:text-black overflow-hidden">
      {/* Ambient background */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute top-0 left-1/4 w-[480px] h-[480px] rounded-full bg-cyan-500/[0.04] blur-[100px]" />
        <div className="absolute bottom-0 right-1/4 w-[400px] h-[400px] rounded-full bg-purple-500/[0.04] blur-[100px]" />
        <div
          className="absolute inset-0 opacity-[0.35]"
          style={{
            backgroundImage:
              "linear-gradient(rgba(148,163,184,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.04) 1px, transparent 1px)",
            backgroundSize: "48px 48px",
          }}
        />
      </div>

      {/* Main card */}
      <div className="relative w-full max-w-5xl grid grid-cols-1 lg:grid-cols-12 rounded-2xl border border-slate-800/80 bg-[#0d1322]/95 shadow-[0_24px_80px_rgba(0,0,0,0.55)] overflow-hidden animate-slide-up">
        {/* Top accent */}
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-500/50 to-transparent" />

        {/* LEFT COLUMN */}
        <div className="lg:col-span-6 p-8 sm:p-10 lg:p-12 bg-[#0a0f1d]/90 border-b lg:border-b-0 lg:border-r border-slate-800/80 flex flex-col justify-between">
          <div className="space-y-7">
            {/* Brand */}
            <div className="flex items-center gap-3.5">
              <div className="relative w-11 h-11 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_24px_rgba(34,211,238,0.12)]">
                <ShieldCheck className="w-5 h-5" />
                <span className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-emerald-400 border-2 border-[#0a0f1d]" />
              </div>
              <div>
                <span className="text-base font-semibold tracking-tight text-white block leading-none">
                  Forensic AI
                </span>
                <span className="text-xs text-slate-400 font-medium mt-1 block">
                  Security Operations Platform
                </span>
              </div>
            </div>

            {/* Headline */}
            <div className="space-y-3">
              <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full border border-cyan-500/20 bg-cyan-500/5">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                <span className="text-[10px] font-mono font-semibold tracking-widest text-cyan-400 uppercase">
                  SOC Workstation
                </span>
              </div>
              <h1 className="text-2xl sm:text-[1.75rem] font-semibold tracking-tight text-white leading-snug">
                Advanced email forensics & threat investigation.
              </h1>
              <p className="text-sm text-slate-400 leading-relaxed max-w-md">
                Triage phishing incidents, verify cryptographic headers, and uncover spoofed sender routing with calibrated neural detection.
              </p>
            </div>

            {/* Capability tags */}
            <div className="flex flex-wrap gap-2">
              {TAGS.map((tag) => (
                <span
                  key={tag}
                  className="text-[10px] px-2.5 py-1 rounded-full border border-slate-700/80 bg-slate-900/50 text-slate-400 font-mono"
                >
                  {tag}
                </span>
              ))}
            </div>

            {/* Value pillars */}
            <div className="space-y-3 pt-1">
              {CAPABILITIES.map((item, idx) => (
                <div
                  key={idx}
                  className="group flex items-start gap-3.5 p-3 -mx-3 rounded-xl hover:bg-slate-800/30 transition-colors duration-200"
                >
                  <div
                    className={`w-9 h-9 rounded-lg border flex items-center justify-center flex-shrink-0 mt-0.5 transition-colors duration-200 ${item.color}`}
                  >
                    <item.icon className="w-4 h-4" />
                  </div>
                  <div>
                    <h3 className="text-xs font-semibold text-slate-200 group-hover:text-white transition-colors">
                      {item.title}
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">{item.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN */}
        <div className="lg:col-span-6 p-8 sm:p-10 lg:p-12 flex flex-col justify-between space-y-6 bg-[#0d1322]">
          <div className="space-y-6">
            {/* Header & tabs */}
            <div className="space-y-4">
              <div>
                <h2 className="text-xl font-semibold text-white tracking-tight">
                  {mode === "login" ? "Sign in to SOC Workstation" : "Create Analyst Account"}
                </h2>
                <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                  {mode === "login"
                    ? "Enter your credentials to access live email telemetry."
                    : "Register your analyst profile for localized incident logs."}
                </p>
              </div>

              <div className="flex p-1 bg-slate-900/80 border border-slate-800 rounded-xl">
                {(["login", "register"] as const).map((tab) => (
                  <button
                    key={tab}
                    type="button"
                    onClick={() => {
                      setMode(tab);
                      setError(null);
                    }}
                    className={`flex-1 py-2 text-xs font-medium rounded-lg transition-all duration-200 ${
                      mode === tab
                        ? "bg-slate-800 text-white shadow-sm ring-1 ring-cyan-500/20"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {tab === "login" ? "Sign In" : "Create Account"}
                  </button>
                ))}
              </div>
            </div>

            {/* Form */}
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-slate-300">Work Email</label>
                <div className="relative group">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500 group-focus-within:text-cyan-400 transition-colors">
                    <Mail className="w-4 h-4" />
                  </div>
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="analyst@agency.gov or name@company.com"
                    className={inputClass}
                  />
                </div>
              </div>

              {mode === "register" && (
                <div className="space-y-1.5 animate-fade-in">
                  <label className="block text-xs font-medium text-slate-300">Designation / Role</label>
                  <select
                    value={role}
                    onChange={(e) => setRole(e.target.value)}
                    className="w-full px-3.5 py-3 bg-slate-900/60 border border-slate-700/60 rounded-xl text-sm text-white focus:outline-none focus:border-cyan-500/70 focus:ring-2 focus:ring-cyan-500/20 transition-all duration-200"
                  >
                    <option value="SOC Analyst">SOC Tier-1 Analyst (Triage & Scan)</option>
                    <option value="Forensic Investigator">Digital Forensics Specialist (Deep Inspection)</option>
                    <option value="Threat Hunter">Incident Commander / Threat Hunter</option>
                    <option value="Security Officer">Security Compliance Officer</option>
                  </select>
                </div>
              )}

              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-slate-300">Password</label>
                <div className="relative group">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500 group-focus-within:text-cyan-400 transition-colors">
                    <KeyRound className="w-4 h-4" />
                  </div>
                  <input
                    type={showPassword ? "text" : "password"}
                    required
                    minLength={6}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="•••••••••••• (min 6 characters)"
                    className={`${inputClass} pr-10`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-slate-500 hover:text-slate-300 transition-colors"
                    aria-label={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {error && (
                <div className="p-3.5 rounded-xl bg-red-500/10 border border-red-500/25 text-xs text-red-400 leading-relaxed animate-fade-in">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="w-full py-3 px-4 rounded-xl bg-cyan-500 hover:bg-cyan-400 active:scale-[0.99] text-slate-950 font-semibold text-sm transition-all flex items-center justify-center gap-2 shadow-[0_4px_20px_rgba(34,211,238,0.25)] hover:shadow-[0_6px_28px_rgba(34,211,238,0.35)] disabled:opacity-50 disabled:cursor-not-allowed disabled:shadow-none"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Authenticating…</span>
                  </>
                ) : (
                  <>
                    <span>{mode === "login" ? "Sign In to Console" : "Create Account & Continue"}</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>

            {/* Divider */}
            <div className="relative flex items-center justify-center">
              <div className="border-t border-slate-800 w-full" />
              <span className="absolute bg-[#0d1322] px-3 text-[10px] text-slate-500 uppercase tracking-widest font-medium">
                Or Quick Access
              </span>
            </div>

            {/* Guest access */}
            <button
              type="button"
              onClick={handleGuestAccess}
              className="w-full py-3 px-4 rounded-xl bg-slate-800/50 hover:bg-slate-800 border border-slate-700/60 hover:border-slate-600 text-sm font-medium text-slate-200 hover:text-white transition-all flex items-center justify-between group"
            >
              <div className="flex items-center gap-2.5">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-60" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-400" />
                </span>
                <span>Explore with Guest Analyst Access</span>
              </div>
              <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-white group-hover:translate-x-0.5 transition-all" />
            </button>
          </div>

          {/* Security notice */}
          <div className="pt-5 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-500">
            <div className="flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5" />
              <span>PBKDF2 SHA-256 Hashed</span>
            </div>
            <span className="font-mono">TLS 1.3 Encrypted</span>
          </div>
        </div>
      </div>
    </div>
  );
};
