import React, { useState } from "react";
import { 
  ShieldCheck, 
  Lock, 
  ArrowRight, 
  CheckCircle2, 
  Eye, 
  EyeOff, 
  Mail, 
  KeyRound, 
  Server, 
  MapPin, 
  Sparkles,
  ChevronRight
} from "lucide-react";
import { apiRequest, parseApiError } from "../config";

interface SocOnboardingProps {
  onComplete: (user?: any) => void;
  onSkip: () => void;
}

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
          data: { email: email.trim(), password }
        });
      }

      const data: any = await apiRequest("/api/auth/login", {
        method: "post",
        data: { email: email.trim(), password }
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

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-4 sm:p-6 lg:p-12 bg-[#090d16] text-slate-100 font-sans selection:bg-cyan-500 selection:text-black">
      
      {/* Container Box */}
      <div className="w-full max-w-5xl grid grid-cols-1 lg:grid-cols-12 rounded-2xl border border-slate-800 bg-[#0d1322] shadow-[0_20px_60px_rgba(0,0,0,0.6)] overflow-hidden">
        
        {/* LEFT COLUMN: Product Overview & Capabilities */}
        <div className="lg:col-span-6 p-8 sm:p-10 lg:p-12 bg-[#0a0f1d] border-b lg:border-b-0 lg:border-r border-slate-800 flex flex-col justify-between space-y-8">
          
          <div className="space-y-6">
            {/* Brand Logo */}
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-sm">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <div>
                <span className="text-base font-semibold tracking-tight text-white block leading-none">Forensic AI</span>
                <span className="text-xs text-slate-400 font-medium">Security Operations Platform</span>
              </div>
            </div>

            {/* Headline */}
            <div className="space-y-2.5">
              <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-white leading-snug">
                Advanced email forensics & threat investigation.
              </h1>
              <p className="text-sm text-slate-400 leading-relaxed">
                Triage phishing incidents, verify cryptographic headers, and uncover spoofed sender routing with calibrated neural detection.
              </p>
            </div>

            {/* Value Pillars */}
            <div className="space-y-4 pt-2">
              {[
                {
                  title: "Dual-Node Geolocation",
                  desc: "Correlates claimed sender identity against physical relay server hardware on an interactive map.",
                  icon: MapPin,
                  color: "text-purple-400 bg-purple-500/10 border-purple-500/20"
                },
                {
                  title: "Zero Synthetic Telemetry",
                  desc: "Strictly verifies RFC 5322 transit headers and official government sovereign registries.",
                  icon: Server,
                  color: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20"
                },
                {
                  title: "Explainable AI & MITRE ATT&CK",
                  desc: "Clear risk scoring with social engineering technique attribution and tamper-proof forensic dossiers.",
                  icon: Sparkles,
                  color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
                }
              ].map((item, idx) => (
                <div key={idx} className="flex items-start gap-3.5">
                  <div className={`w-8 h-8 rounded-lg border flex items-center justify-center flex-shrink-0 mt-0.5 ${item.color}`}>
                    <item.icon className="w-4 h-4" />
                  </div>
                  <div>
                    <h3 className="text-xs font-semibold text-slate-200">{item.title}</h3>
                    <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">{item.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Bottom Trust Badge */}
          <div className="pt-6 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>Government & Enterprise SOC Ready</span>
            </div>
            <span className="text-[11px] text-slate-400">v3.0 Production</span>
          </div>

        </div>

        {/* RIGHT COLUMN: Clean Sign In / Register Form */}
        <div className="lg:col-span-6 p-8 sm:p-10 lg:p-12 flex flex-col justify-between space-y-6 bg-[#0d1322]">
          
          <div className="space-y-6">
            
            {/* Header & Tabs */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-xl font-semibold text-white tracking-tight">
                    {mode === "login" ? "Sign in to SOC Workstation" : "Create Analyst Account"}
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">
                    {mode === "login" 
                      ? "Enter your credentials to access live email telemetry." 
                      : "Register your analyst profile for localized incident logs."}
                  </p>
                </div>
              </div>

              {/* Mode Switcher */}
              <div className="flex p-1 bg-slate-900/90 border border-slate-800 rounded-xl">
                <button
                  type="button"
                  onClick={() => { setMode("login"); setError(null); }}
                  className={`flex-1 py-1.5 text-xs font-medium rounded-lg transition-all ${
                    mode === "login" 
                      ? "bg-slate-800 text-white shadow-sm" 
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  Sign In
                </button>
                <button
                  type="button"
                  onClick={() => { setMode("register"); setError(null); }}
                  className={`flex-1 py-1.5 text-xs font-medium rounded-lg transition-all ${
                    mode === "register" 
                      ? "bg-slate-800 text-white shadow-sm" 
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  Create Account
                </button>
              </div>
            </div>

            {/* Form */}
            <form onSubmit={handleSubmit} className="space-y-4">
              
              {/* Work Email */}
              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-slate-300">Work Email</label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                    <Mail className="w-4 h-4" />
                  </div>
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="analyst@agency.gov or name@company.com"
                    className="w-full pl-10 pr-3.5 py-2.5 bg-slate-900/80 border border-slate-700/80 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
                  />
                </div>
              </div>

              {/* Role selector on Register */}
              {mode === "register" && (
                <div className="space-y-1.5">
                  <label className="block text-xs font-medium text-slate-300">Designation / Role</label>
                  <select
                    value={role}
                    onChange={(e) => setRole(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-slate-900/80 border border-slate-700/80 rounded-xl text-xs text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
                  >
                    <option value="SOC Analyst">SOC Tier-1 Analyst (Triage & Scan)</option>
                    <option value="Forensic Investigator">Digital Forensics Specialist (Deep Inspection)</option>
                    <option value="Threat Hunter">Incident Commander / Threat Hunter</option>
                    <option value="Security Officer">Security Compliance Officer</option>
                  </select>
                </div>
              )}

              {/* Password */}
              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-slate-300">Password</label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                    <KeyRound className="w-4 h-4" />
                  </div>
                  <input
                    type={showPassword ? "text" : "password"}
                    required
                    minLength={6}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="•••••••••••• (min 6 characters)"
                    className="w-full pl-10 pr-10 py-2.5 bg-slate-900/80 border border-slate-700/80 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-slate-500 hover:text-slate-300"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Error Message */}
              {error && (
                <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-xs text-red-400 leading-relaxed">
                  {error}
                </div>
              )}

              {/* Submit Button */}
              <button
                type="submit"
                disabled={loading}
                className="w-full py-2.5 px-4 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs transition-all flex items-center justify-center gap-2 shadow-sm disabled:opacity-50"
              >
                {loading ? (
                  <span>Authenticating…</span>
                ) : (
                  <>
                    <span>{mode === "login" ? "Sign In to Console" : "Create Account & Continue"}</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>

            {/* Divider */}
            <div className="relative flex items-center justify-center my-4">
              <div className="border-t border-slate-800 w-full" />
              <span className="bg-[#0d1322] px-3 text-[11px] text-slate-400 uppercase tracking-wider font-medium">
                Or Quick Access
              </span>
            </div>

            {/* 1-Click Guest Analyst Mode */}
            <button
              type="button"
              onClick={handleGuestAccess}
              className="w-full py-2.5 px-4 rounded-xl bg-slate-800/80 hover:bg-slate-800 border border-slate-700/80 text-xs font-medium text-slate-200 hover:text-white transition-all flex items-center justify-between group"
            >
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 group-hover:animate-ping" />
                <span>Explore with Guest Analyst Access</span>
              </div>
              <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-white group-hover:translate-x-0.5 transition-all" />
            </button>

          </div>

          {/* Security Notice */}
          <div className="pt-4 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
            <div className="flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-slate-400" />
              <span>PBKDF2 SHA-256 Hashed</span>
            </div>
            <span>TLS 1.3 Encrypted</span>
          </div>

        </div>

      </div>

    </div>
  );
};
