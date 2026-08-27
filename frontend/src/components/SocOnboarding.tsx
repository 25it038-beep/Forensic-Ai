import React from "react";
import {
  ShieldCheck,
  Lock,
  ArrowRight,
  Server,
  MapPin,
  Sparkles,
  ChevronRight,
  UserPlus,
  LogIn
} from "lucide-react";
import { SignInButton, SignUpButton, useUser } from "@clerk/react";

interface SocOnboardingProps {
  onComplete: () => void;
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
  const { isSignedIn, user } = useUser();

  const handleGuestAccess = () => {
    onSkip();
  };

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
            {/* Header */}
            <div className="space-y-2">
              <h2 className="text-xl font-semibold text-white tracking-tight">
                {isSignedIn ? "Authenticated Session" : "Access Security Console"}
              </h2>
              <p className="text-xs text-slate-400 leading-relaxed">
                {isSignedIn
                  ? `Signed in as ${user?.primaryEmailAddress?.emailAddress || "Analyst"}. Click below to enter your workspace.`
                  : "Sign in with Clerk for isolated incident logs, or continue as a guest analyst."}
              </p>
            </div>

            {/* Clerk Sign In / Sign Up Action Options */}
            {isSignedIn ? (
              <div className="space-y-3 pt-2">
                <button
                  onClick={onComplete}
                  className="w-full py-3.5 px-4 rounded-xl bg-cyan-500 hover:bg-cyan-400 active:scale-[0.99] text-slate-950 font-bold text-sm transition-all flex items-center justify-center gap-2 shadow-[0_4px_20px_rgba(34,211,238,0.25)]"
                >
                  <span>Enter SOC Dashboard</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            ) : (
              <div className="space-y-3 pt-2">
                {/* Primary Sign In Button */}
                <SignInButton mode="modal">
                  <button className="w-full py-3.5 px-4 rounded-xl bg-sky-500 hover:bg-sky-400 active:scale-[0.99] text-slate-950 font-bold text-sm transition-all flex items-center justify-center gap-2 shadow-[0_4px_20px_rgba(14,165,233,0.25)] hover:shadow-[0_6px_28px_rgba(14,165,233,0.35)]">
                    <LogIn className="w-4 h-4" />
                    <span>Sign In with Clerk</span>
                    <ArrowRight className="w-4 h-4 ml-1" />
                  </button>
                </SignInButton>

                {/* Create Account Button */}
                <SignUpButton mode="modal">
                  <button className="w-full py-3.5 px-4 rounded-xl bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700/80 text-white font-medium text-sm transition-all flex items-center justify-center gap-2 shadow-sm">
                    <UserPlus className="w-4 h-4 text-sky-400" />
                    <span>Create Free Analyst Account</span>
                  </button>
                </SignUpButton>
              </div>
            )}

            {/* Divider */}
            <div className="relative flex items-center justify-center pt-2">
              <div className="border-t border-slate-800 w-full" />
              <span className="absolute bg-[#0d1322] px-3 text-[10px] text-slate-500 uppercase tracking-widest font-medium">
                No Account Needed
              </span>
            </div>

            {/* Guest access — allows users without account to enter */}
            <button
              type="button"
              onClick={handleGuestAccess}
              className="w-full py-3 px-4 rounded-xl bg-slate-800/40 hover:bg-slate-800 border border-slate-700/50 hover:border-slate-600 text-sm font-medium text-slate-200 hover:text-white transition-all flex items-center justify-between group"
            >
              <div className="flex items-center gap-2.5">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-60" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-400" />
                </span>
                <span>Continue as Guest (Try Threat Analyzer)</span>
              </div>
              <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-white group-hover:translate-x-0.5 transition-all" />
            </button>
          </div>

          {/* Security notice */}
          <div className="pt-5 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-500">
            <div className="flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5" />
              <span>Clerk Enterprise Auth</span>
            </div>
            <span className="font-mono">TLS 1.3 NIST Compliant</span>
          </div>
        </div>
      </div>
    </div>
  );
};
