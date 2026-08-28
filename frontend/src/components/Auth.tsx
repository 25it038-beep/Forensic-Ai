import React, { useState } from "react";
import { Shield, Key, CheckCircle } from "lucide-react";
import { SignIn, SignUp, UserProfile, useUser, useClerk } from "@clerk/clerk-react";

interface AuthProps {
  onAuthChange?: () => void;
}

export const Auth: React.FC<AuthProps> = () => {
  const { isSignedIn, user } = useUser();
  const { signOut } = useClerk();
  const [authMode, setAuthMode] = useState<"signin" | "signup">("signin");

  if (isSignedIn && user) {
    return (
      <div className="space-y-6 max-w-4xl mx-auto">
        {/* Active Session Banner */}
        <div className="p-5 rounded-2xl border border-sky-500/30 bg-sky-950/20 backdrop-blur flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-12 h-12 rounded-xl bg-sky-500/10 border border-sky-500/30 flex items-center justify-center shrink-0 overflow-hidden">
              {user.imageUrl ? (
                <img src={user.imageUrl} alt={user.fullName || "User"} className="w-10 h-10 rounded-lg object-cover" />
              ) : (
                <Shield className="w-6 h-6 text-sky-400" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white font-mono">
                  {user.fullName || user.primaryEmailAddress?.emailAddress?.split("@")[0] || "SOC Analyst"}
                </h3>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                  <CheckCircle className="w-3 h-3" /> Clerk Verified
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                {user.primaryEmailAddress?.emailAddress}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5 w-full md:w-auto">
            <button
              onClick={() => signOut()}
              className="w-full md:w-auto px-4 py-2 rounded-xl border border-rose-500/30 bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 font-mono text-xs font-semibold transition"
            >
              Sign Out
            </button>
          </div>
        </div>

        {/* Clerk Profile Manager */}
        <div className="p-4 rounded-2xl border border-white/[0.08] bg-black/40 shadow-xl overflow-hidden flex justify-center">
          <UserProfile routing="hash" />
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-xl mx-auto space-y-6 py-6">
      {/* Header Info */}
      <div className="text-center space-y-2">
        <div className="w-12 h-12 rounded-2xl bg-sky-500/10 border border-sky-500/30 text-sky-400 flex items-center justify-center mx-auto shadow-lg shadow-sky-500/10">
          <Key className="w-6 h-6" />
        </div>
        <h2 className="text-xl font-bold font-mono text-white tracking-tight">
          SOC Analyst Authentication
        </h2>
        <p className="text-xs text-slate-400 font-mono max-w-sm mx-auto">
          Secure multi-factor identity powered by Clerk. Authenticate to sync your forensic telemetry and incident investigations.
        </p>
      </div>

      {/* Mode Switcher */}
      <div className="flex justify-center gap-2 p-1 rounded-xl bg-white/[0.04] border border-white/[0.08] max-w-xs mx-auto">
        <button
          onClick={() => setAuthMode("signin")}
          className={`flex-1 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
            authMode === "signin"
              ? "bg-sky-500 text-slate-950 shadow"
              : "text-slate-400 hover:text-white"
          }`}
        >
          Sign In
        </button>
        <button
          onClick={() => setAuthMode("signup")}
          className={`flex-1 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
            authMode === "signup"
              ? "bg-sky-500 text-slate-950 shadow"
              : "text-slate-400 hover:text-white"
          }`}
        >
          Sign Up
        </button>
      </div>

      {/* Clerk Embedded Authentication Card */}
      <div className="flex justify-center">
        {authMode === "signin" ? (
          <SignIn routing="hash" />
        ) : (
          <SignUp routing="hash" />
        )}
      </div>
    </div>
  );
};
