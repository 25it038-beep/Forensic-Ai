import React, { useEffect, useRef, useState } from "react";
import { MessageCircle, X, Send, Sparkles, Shield, Bot, User, Trash2, Copy, Check, Database, FileText } from "lucide-react";
import { apiRequest, parseApiError } from "../config";

interface ChatMsg { role: "user" | "assistant"; content: string; at: number; }
interface RecentIncident { id?: number; classification: string; risk_score: number; subject?: string; sender?: string; threat_type?: string; created_at?: string; }

export const ChatPanel: React.FC = () => {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMsg[]>(() => {
    try { const raw = localStorage.getItem("forensic_chat_history"); return raw ? JSON.parse(raw) : []; } catch { return []; }
  });
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState<number | null>(null);
  const [recent, setRecent] = useState<RecentIncident[]>([]);
  const listRef = useRef<HTMLDivElement>(null);

  const fetchRecent = async () => {
    try {
      const data = await apiRequest<RecentIncident[]>("/api/history?limit=5", { method: "get", timeout: 8000 });
      setRecent(data || []);
      if (data && data[0] && !localStorage.getItem("forensic_last_scan")) {
        try { localStorage.setItem("forensic_last_scan", JSON.stringify(data[0])); } catch {}
      }
    } catch {}
  };
  useEffect(() => { fetchRecent(); }, []);
  useEffect(() => { if (open) fetchRecent(); }, [open]);

  useEffect(() => {
    try { localStorage.setItem("forensic_chat_history", JSON.stringify(messages.slice(-24))); } catch {}
    if (listRef.current) listRef.current.scrollTop = listRef.current.scrollHeight;
  }, [messages]);

  const send = async (text: string) => {
    const trimmed = text.trim();
    if (!trimmed) return;
    const userMsg: ChatMsg = { role: "user", content: trimmed, at: Date.now() };
    setMessages(m => [...m, userMsg]);
    setInput("");
    setLoading(true);
    try {
      let scanContext: any = null;
      try { const raw = localStorage.getItem("forensic_last_scan"); if (raw) scanContext = JSON.parse(raw); } catch {}
      const payload: any = {
        message: trimmed,
        conversation: messages.slice(-8).map(m => ({ role: m.role, content: m.content })),
        scan_context: scanContext,
        use_history: true
      };
      const res = await apiRequest<{ reply: string }>("/api/chat", { method: "post", data: payload, timeout: 30000 });
      setMessages(m => [...m, { role: "assistant", content: res.reply, at: Date.now() }]);
    } catch (e: any) {
      setMessages(m => [...m, { role: "assistant", content: `⚠️ SOC Support error: ${parseApiError(e)}`, at: Date.now() }]);
    } finally { setLoading(false); }
  };

  useEffect(() => {
    const handler = (ev: any) => {
      const scan = ev.detail;
      if (!scan) return;
      try { localStorage.setItem("forensic_last_scan", JSON.stringify(scan)); } catch {}
      fetchRecent();
      setOpen(true);
      const prompt = `As SOC Support, give tailored recommendations for this scan. Classification: ${scan.classification}, Risk: ${scan.risk_score}/100, Confidence: ${scan.confidence_score}%, Threat: ${scan.threat_type || "Unknown"}, Indicators: ${Object.keys(scan.detected_indicators || {}).filter((k: string) => scan.detected_indicators[k]).join(", ") || "none"}. Use scanned incidents as reference and explain next steps for the analyst.`;
      setTimeout(() => send(prompt), 350);
    };
    window.addEventListener("forensic:scan-complete" as any, handler as any);
    return () => window.removeEventListener("forensic:scan-complete" as any, handler as any);
  }, [messages]);

  const clear = () => {
    if (!confirm("Clear SOC chat history?")) return;
    setMessages([]);
    localStorage.removeItem("forensic_chat_history");
  };
  const copy = (text: string, idx: number) => { navigator.clipboard.writeText(text); setCopied(idx); setTimeout(() => setCopied(null), 1500); };
  const useIncidentAsContext = (inc: RecentIncident) => {
    const txt = `Explain incident #${inc.id} — ${inc.classification} risk ${inc.risk_score}/100 — ${inc.subject || inc.threat_type || ""} from ${inc.sender || "unknown"}. Use scanned incidents as reference.`;
    send(txt);
  };

  return (
    <>
      {/* Floating rounded widget — non-interrupting */}
      <button
        onClick={() => setOpen(!open)}
        className="fixed bottom-5 right-5 z-50 w-14 h-14 rounded-full shadow-xl border flex items-center justify-center hover:scale-[1.04] active:scale-[0.97] transition"
        style={{ background: open ? "#0f172a" : "#ffffff", color: open ? "white" : "#0f172a", borderColor: open ? "#0f172a" : "#e2e8f0" }}
        title={open ? "Close SOC Support" : "Open SOC Support — AI chat"}
      >
        {open ? <X className="w-5 h-5" /> : <MessageCircle className="w-5 h-5" />}
        {!open && recent.length > 0 && (
          <span className="absolute -top-1 -right-1 w-5 h-5 rounded-full bg-red-600 text-white text-[10px] grid place-items-center border-2 border-white">
            {recent.filter(r => r.classification === "Phishing").length || recent.length}
          </span>
        )}
      </button>

      {/* Floating panel — non-interrupting overlay */}
      {open && (
        <div className="fixed bottom-20 right-5 z-40 w-[380px] max-w-[94vw] h-[520px] rounded-2xl border shadow-2xl flex flex-col overflow-hidden" style={{ background: "var(--panel)", borderColor: "var(--border)" }}>
          <div className="px-4 py-3 border-b flex items-center justify-between" style={{ background: "var(--panel-soft)", borderColor: "var(--border)" }}>
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-xl bg-slate-900 text-white grid place-items-center">
                <Shield className="w-4 h-4" />
              </div>
              <div>
                <div className="text-[13px] font-semibold flex items-center gap-1.5" style={{ color: "var(--text)" }}>
                  SOC Support <span className="text-[10px] px-1.5 py-0.5 rounded-full border bg-emerald-50 text-emerald-700 border-emerald-200">Live</span>
                </div>
                <div className="text-[11px] flex items-center gap-1" style={{ color: "var(--muted)" }}>
                  <Database className="w-3 h-3" /> {recent.length} incidents referenced
                </div>
              </div>
            </div>
            <button onClick={clear} className="p-1.5 rounded-lg border hover:bg-white" style={{ borderColor: "var(--border)", color: "var(--muted)" }} title="Clear history">
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="px-3 py-2.5 border-y flex gap-1.5 overflow-x-auto" style={{ borderColor: "var(--border)", background: "var(--panel)" }}>
            <span className="text-[10px] font-medium px-2 py-1 rounded-full border shrink-0 inline-flex items-center gap-1" style={{ background: "var(--panel-soft)", borderColor: "var(--border)", color: "var(--muted)" }}>
              <FileText className="w-3 h-3" /> References:
            </span>
            {recent.slice(0, 5).map(r => (
              <button
                key={r.id}
                onClick={() => useIncidentAsContext(r)}
                className="px-2.5 py-1 rounded-full border text-[11px] font-medium whitespace-nowrap hover:bg-slate-50 flex items-center gap-1.5 shrink-0"
                style={{ background: r.classification==="Phishing" ? "#fef2f2" : r.classification==="Suspicious" ? "#fffbeb" : "#ecfdf5", borderColor: r.classification==="Phishing" ? "#fecaca" : r.classification==="Suspicious" ? "#fde68a" : "#a7f3d0", color: r.classification==="Phishing" ? "#991b1b" : r.classification==="Suspicious" ? "#92400e" : "#065f46" }}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${r.classification==="Phishing"?"bg-red-500":r.classification==="Suspicious"?"bg-amber-500":"bg-emerald-500"}`} />
                #{r.id} {r.classification} · {r.risk_score}
              </button>
            ))}
            {recent.length===0 && <span className="text-[11px] py-1" style={{ color: "var(--faint)" }}>No scans yet</span>}
          </div>

          <div className="px-3 py-2 flex gap-1.5 overflow-x-auto border-b" style={{ borderColor: "var(--border)", background: "var(--panel)" }}>
            {["Explain last scan","Next steps?","Is this BEC?","Summarize trends"].map(q => (
              <button key={q} onClick={() => send(q)} className="px-2.5 py-1 rounded-full border text-[11px] font-medium whitespace-nowrap hover:bg-slate-50" style={{ background: "var(--panel-soft)", borderColor: "var(--border)", color: "var(--text-soft)" }}>
                {q}
              </button>
            ))}
          </div>

          <div ref={listRef} className="flex-1 overflow-auto p-3 space-y-3" style={{ background: "var(--bg)" }}>
            {messages.length === 0 && (
              <div className="rounded-xl border p-3 text-[12px] leading-5" style={{ background: "var(--panel)", borderColor: "var(--border)", color: "var(--muted)" }}>
                <div className="flex items-center gap-2 font-medium" style={{ color: "var(--text)" }}><Sparkles className="w-3.5 h-3.5" /> SOC Support — how can I help?</div>
                <ul className="mt-2 space-y-1 list-disc list-inside">
                  <li>Ask about any incident — I reference your scanned history.</li>
                  <li>After each analysis I auto-suggest SOC next steps.</li>
                  <li>Try: “Why is incident #12 phishing?”</li>
                </ul>
              </div>
            )}
            {messages.map((m, idx) => (
              <div key={idx} className={`flex gap-2 ${m.role === "user" ? "justify-end" : "justify-start"}`}>
                {m.role === "assistant" && <div className="w-6 h-6 rounded-full bg-slate-900 text-white grid place-items-center shrink-0 mt-0.5"><Bot className="w-3 h-3" /></div>}
                <div className={`max-w-[78%] rounded-2xl px-3 py-2.5 text-[13px] leading-5 border ${m.role === "user" ? "bg-slate-900 text-white border-slate-900" : ""}`} style={m.role === "assistant" ? { background: "var(--panel)", borderColor: "var(--border)", color: "var(--text)" } : {}}>
                  <div className="whitespace-pre-wrap break-words">{m.content}</div>
                  {m.role === "assistant" && (
                    <div className="mt-2 flex items-center gap-1">
                      <button onClick={() => copy(m.content, idx)} className="p-1 rounded-md border hover:bg-slate-50" style={{ borderColor: "var(--border)", color: "var(--muted)" }} title="Copy">
                        {copied === idx ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                      </button>
                      <span className="text-[10px]" style={{ color: "var(--faint)" }}>{new Date(m.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
                    </div>
                  )}
                </div>
                {m.role === "user" && <div className="w-6 h-6 rounded-full bg-slate-200 text-slate-700 grid place-items-center shrink-0 mt-0.5"><User className="w-3 h-3" /></div>}
              </div>
            ))}
            {loading && (
              <div className="flex gap-2">
                <div className="w-6 h-6 rounded-full bg-slate-900 text-white grid place-items-center shrink-0"><Bot className="w-3 h-3" /></div>
                <div className="rounded-2xl px-3 py-2.5 border text-[13px]" style={{ background: "var(--panel)", borderColor: "var(--border)", color: "var(--muted)" }}>
                  <span className="inline-flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-slate-400 animate-bounce" /><span className="w-1.5 h-1.5 rounded-full bg-slate-400 animate-bounce" style={{ animationDelay: "150ms" }} /><span className="w-1.5 h-1.5 rounded-full bg-slate-400 animate-bounce" style={{ animationDelay: "300ms" }} /></span> Consulting {recent.length} incidents…
                </div>
              </div>
            )}
          </div>

          <div className="p-3 border-t flex gap-2" style={{ background: "var(--panel)", borderColor: "var(--border)" }}>
            <input
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(input); } }}
              placeholder="Ask SOC Support…"
              className="flex-1 rounded-xl border px-3 py-2.5 text-[13px] focus:outline-none focus:ring-1"
              style={{ background: "var(--panel-soft)", borderColor: "var(--border)", color: "var(--text)" }}
            />
            <button onClick={() => send(input)} disabled={loading || !input.trim()} className="w-9 h-9 rounded-xl grid place-items-center shrink-0 disabled:opacity-50" style={{ background: "var(--text)", color: "var(--bg)" }} title="Send">
              <Send className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </>
  );
};
