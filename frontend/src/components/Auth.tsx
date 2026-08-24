import React, { useState, useEffect } from "react";
import { User, LogIn, UserPlus, LogOut, Shield } from "lucide-react";
import { apiRequest, parseApiError } from "../config";

interface AuthProps {
  onAuthChange?: () => void;
}

export const Auth: React.FC<AuthProps> = ({ onAuthChange }) => {
  const [mode, setMode] = useState<"login"|"register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [user, setUser] = useState<any>(null);

  const tokenKey = "forensic_jwt";
  const getToken = () => localStorage.getItem(tokenKey);

  const fetchMe = async () => {
    const t = getToken();
    if (!t) { setUser(null); return; }
    try {
      const me = await apiRequest<any>("/api/auth/me", { headers: { Authorization: `Bearer ${t}` } as any });
      setUser(me);
    } catch {
      localStorage.removeItem(tokenKey);
      setUser(null);
    }
  };

  useEffect(() => { fetchMe(); }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null); setLoading(true);
    try {
      if (mode === "register") {
        await apiRequest("/api/auth/register", { method: "post", data: { email, password } });
        // auto login after register
      }
      const data: any = await apiRequest("/api/auth/login", { method: "post", data: { email, password } });
      localStorage.setItem(tokenKey, data.access_token);
      setUser(data.user);
      setEmail(""); setPassword("");
      onAuthChange?.();
    } catch (err: any) {
      setError(parseApiError(err));
    } finally { setLoading(false); }
  };

  const logout = () => {
    localStorage.removeItem(tokenKey);
    setUser(null);
    onAuthChange?.();
  };

  if (user) {
    return (
      <div className="panel rounded-xl p-5 space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-full bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center">
            <User className="w-4 h-4 text-emerald-400" />
          </div>
          <div>
            <p className="font-code text-xs font-bold text-white">{user.email}</p>
            <p className="font-code text-[9px] text-slate-500 uppercase">{user.role} · {user.is_verified ? "verified" : "active"}</p>
          </div>
          <Shield className="w-4 h-4 text-emerald-400 ml-auto" />
        </div>
        <div className="flex gap-2">
          <button onClick={logout} className="btn-danger flex items-center gap-2">
            <LogOut className="w-3.5 h-3.5" /> LOGOUT
          </button>
          <a href="#" onClick={(e)=>{e.preventDefault(); fetchMe();}} className="px-3 py-2 rounded-lg bg-white/[0.04] border border-white/[0.06] font-code text-[10px] text-slate-400 hover:text-white">REFRESH</a>
        </div>
        <p className="font-code text-[9px] text-slate-600">JWT stored in localStorage. History & stats are now scoped to your account. Admin sees all.</p>
      </div>
    );
  }

  return (
    <div className="panel rounded-xl p-5 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="font-orbitron text-sm font-bold text-white flex items-center gap-2">
          {mode === "login" ? <LogIn className="w-4 h-4 text-cyan-400"/> : <UserPlus className="w-4 h-4 text-cyan-400"/>}
          {mode === "login" ? "SOC LOGIN" : "CREATE ACCOUNT"}
        </h3>
        <button onClick={()=>{setMode(mode==="login"?"register":"login"); setError(null);}} className="font-code text-[10px] text-cyan-400 hover:text-cyan-300 underline">
          {mode === "login" ? "Need account? Register" : "Have account? Login"}
        </button>
      </div>

      <form onSubmit={handleSubmit} className="space-y-3">
        <input
          type="email" required value={email} onChange={(e)=>setEmail(e.target.value)}
          placeholder="analyst@soc.example"
          className="w-full bg-[#02040a] border border-white/[0.07] rounded-lg px-3 py-2.5 font-code text-[11px] text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500/30"
        />
        <input
          type="password" required minLength={6} value={password} onChange={(e)=>setPassword(e.target.value)}
          placeholder="•••••••• (min 6)"
          className="w-full bg-[#02040a] border border-white/[0.07] rounded-lg px-3 py-2.5 font-code text-[11px] text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500/30"
        />
        {error && <div className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/20 font-code text-[10px] text-red-400">{error}</div>}
        <button type="submit" disabled={loading} className="w-full btn-primary">
          {loading ? "PROCESSING..." : mode==="login" ? "LOGIN & LOAD TELEMETRY" : "REGISTER & LOGIN"}
        </button>
      </form>

      <p className="font-code text-[9px] text-slate-600 text-center">No email verification required in demo. Passwords hashed with PBKDF2.</p>
    </div>
  );
};
