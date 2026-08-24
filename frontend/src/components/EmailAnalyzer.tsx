import React, { useState, useRef, useEffect } from "react";
import {
  Shield, AlertTriangle, AlertCircle, FileText,
  Download, Globe, MapPin, Hash, Copy, Check,
  Cpu, Radio, DollarSign, ChevronRight,
  Eye, RefreshCw, Link, UserCheck
} from "lucide-react";
import { GeoMap, type GeoPoint } from "./GeoMap";
import { apiRequest, parseApiError, executeWithRetry } from "../config";

/* ── Types ── */
interface KeywordImportance { word: string; weight: number; type: string; }
interface VirusTotalResult { malicious: number; harmless: number; undetected: number; suspicious: number; reputation: number; community_votes_harmless: number; community_votes_malicious: number; }
interface WhoisResult { domain_name?: string; registrar?: string; registration_date?: string; expiration_date?: string; name_servers?: string; country?: string; domain_age_days?: number; is_new_domain?: boolean; }
interface EmailAuthResult { spf: string; dkim: string; dmarc: string; is_authenticated: boolean; }
interface AttachmentInfo { filename: string; risk_level: string; reason: string; action: string; }
interface GeoLocationResult { ip?: string; country?: string; country_code?: string; city?: string; region?: string; latitude?: number; longitude?: number; isp?: string; asn?: string; org?: string; timezone?: string; verification_source?: string; }
interface EmailHop { hop_number: number; from_server?: string; by_server?: string; ip?: string; timestamp?: string; delay_seconds?: number; geo?: GeoLocationResult; }
interface HeaderForensics { originating_ip?: string; originating_geo?: GeoLocationResult; hops: EmailHop[]; return_path?: string; reply_to?: string; from_header?: string; message_id?: string; mailer?: string; return_path_mismatch: boolean; display_name_spoofed: boolean; suspicious_mailer: boolean; }
interface AttachmentForensics { filename: string; size_bytes: number; md5: string; sha1: string; sha256: string; mime_type: string; magic_bytes_match: boolean; is_disguised_executable: boolean; risk_level: string; details: string; }
interface UrlForensics { punycode?: string; is_homograph: boolean; typosquatting_target?: string; levenshtein_distance?: number; redirect_hops: string[]; final_destination?: string; geo?: GeoLocationResult; }
interface BecAnalysisResult { is_bec_threat: boolean; bec_type: string; urgency_level: string; detected_patterns: string[]; }
interface AttributionIntelligence { probable_actor_type: string; attribution_confidence: number; infrastructure_type: string; suspected_campaign?: string; vpn_or_proxy_detected: boolean; tor_detected: boolean; threat_actor_indicators: string[]; }
interface GraphNode { id: string; label: string; type: string; threat_level: string; }
interface GraphLink { source: string; target: string; relationship: string; }
interface CorrelationGraph { nodes: GraphNode[]; links: GraphLink[]; }
interface DigitalForensicsResult { header_forensics?: HeaderForensics; attachment_forensics: AttachmentForensics[]; url_forensics?: UrlForensics; origin_geolocation?: GeoLocationResult; sender_geolocation?: GeoLocationResult; forensic_risk_score: number; forensic_flags: string[]; bec_analysis?: BecAnalysisResult; attribution?: AttributionIntelligence; correlation_graph?: CorrelationGraph; }
interface MitreMapping { id: string; name: string; description: string; }
interface LlmAnalysisResult { danger_explanation: string; social_engineering_techniques: string[]; indicators_of_compromise: string[]; safety_recommendations: string[]; mitre_mappings: MitreMapping[]; }
interface PredictResponse { id?: number; subject?: string; sender?: string; classification: string; confidence_score: number; risk_score: number; explanation: string; detected_indicators: Record<string, boolean>; highlighted_text: string; xai_keywords?: KeywordImportance[]; created_at?: string; threat_type?: string; virustotal_results?: VirusTotalResult; whois_results?: WhoisResult; email_auth_results?: EmailAuthResult; attachment_analysis?: AttachmentInfo[]; llm_analysis?: LlmAnalysisResult; geolocation?: GeoLocationResult; sender_geolocation?: GeoLocationResult; forensics?: DigitalForensicsResult; ocr_extracted_text?: string; }
interface UrlAnalyzeResponse { id?: number; url: string; domain: string; risk_score: number; status: string; reasons: string[]; threat_type: string; advice: string; virustotal_results?: VirusTotalResult; whois_results?: WhoisResult; geolocation?: GeoLocationResult; sender_geolocation?: GeoLocationResult; forensics?: DigitalForensicsResult; }
interface Props { onScanCompleted: () => void; initialText?: string | null; }

const clsf = (c: string) =>
  c === "Phishing" ? { label: "PHISHING",   col: "#ff2d55", glow: "text-glow-red",   bg: "panel-red",   dot: "bg-red-400"     }
  : c === "Suspicious" ? { label: "SUSPICIOUS", col: "#ffb800", glow: "text-glow-amber", bg: "panel-amber", dot: "bg-amber-400"  }
  : { label: "SAFE",      col: "#00ff9d", glow: "text-glow-green", bg: "panel-green", dot: "bg-emerald-400" };

export const EmailAnalyzer: React.FC<Props> = ({ onScanCompleted, initialText }) => {
  const [mode, setMode]         = useState<"email"|"url"|"bulk">("email");
  const [tab,  setTab]          = useState<"overview"|"geo"|"graph"|"bec"|"hashes"|"intel"|"mitre">("overview");
  const [text, setText]         = useState("");
  const [url,  setUrl]          = useState("");
  const [bulkText, setBulkText] = useState("");
  const [bulkRes, setBulkRes]   = useState<PredictResponse[] | null>(null);
  const [emailRes, setEmailRes] = useState<PredictResponse | null>(null);
  const [urlRes,   setUrlRes]   = useState<UrlAnalyzeResponse | null>(null);
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState<string | null>(null);
  const [copied,   setCopied]   = useState<string | null>(null);
  const reportRef = useRef<HTMLDivElement>(null);

  // Demo: when Dashboard triggers Run Live Demo, auto-fill and scan
  useEffect(() => {
    if (initialText) {
      setText(initialText);
      setMode("email");
      setError(null);
      setTimeout(() => {
        (async () => {
          setLoading(true); setError(null); setEmailRes(null);
          try {
            const data = await executeWithRetry(() => apiRequest<PredictResponse>("/api/predict", { method: "post", data: { text: initialText } }));
            setEmailRes(data);
            setTab("overview"); onScanCompleted();
            try {
              const payload: any = { ...data, textPreview: initialText.slice(0, 300) };
              window.dispatchEvent(new CustomEvent("forensic:scan-complete", { detail: payload }));
              localStorage.setItem("forensic_last_scan", JSON.stringify(payload));
            } catch {}
          } catch (e) { setError(parseApiError(e)); }
          finally { setLoading(false); }
        })();
      }, 500);
    }
  }, [initialText]);

  const copy = (v: string, label: string) => {
    navigator.clipboard.writeText(v);
    setCopied(label);
    setTimeout(() => setCopied(null), 2000);
  };

  const clear = () => {
    setText(""); setEmailRes(null); setUrlRes(null); setBulkRes(null); setBulkText("");
    setError(null); setUrl(""); setTab("overview");
  };

  const scanEmail = async () => {
    if (!text.trim()) { setError("Paste email content to analyze."); return; }
    setLoading(true); setError(null); setEmailRes(null);
    try {
      const data = await executeWithRetry(() => apiRequest<PredictResponse>("/api/predict", { method: "post", data: { text } }));
      setEmailRes(data);
      setTab("overview"); onScanCompleted();
      // Notify chat for auto-recommendations (all scan data)
      try {
        const payload = { ...data, textPreview: text.slice(0, 300) };
        window.dispatchEvent(new CustomEvent("forensic:scan-complete", { detail: payload }));
        localStorage.setItem("forensic_last_scan", JSON.stringify(payload));
      } catch {}
    } catch (e) { setError(parseApiError(e)); }
    finally { setLoading(false); }
  };

  const scanUrl = async () => {
    if (!url.trim()) { setError("Enter a URL."); return; }
    setLoading(true); setError(null); setUrlRes(null);
    try {
      const data = await executeWithRetry(() => apiRequest<UrlAnalyzeResponse>("/api/analyze-url", { method: "post", data: { url } }));
      setUrlRes(data); setTab("overview"); onScanCompleted();
      try {
        const payload: any = { ...data, classification: (data as any).status || (data as any).classification, textPreview: url, url };
        window.dispatchEvent(new CustomEvent("forensic:scan-complete", { detail: payload }));
        localStorage.setItem("forensic_last_scan", JSON.stringify(payload));
      } catch {}
    } catch (e) { setError(parseApiError(e)); }
    finally { setLoading(false); }
  };

  const scanBulk = async () => {
    const texts = bulkText.split("\n---\n").map(s=>s.trim()).filter(Boolean);
    if (texts.length===0 || texts.length>20) { setError("Enter 1-20 emails separated by a line with ---"); return; }
    setLoading(true); setError(null); setBulkRes(null);
    try {
      const data = await executeWithRetry(() => apiRequest<PredictResponse[]>("/api/bulk/predict", { method:"post", data:{ texts } }));
      setBulkRes(data); onScanCompleted();
      try {
        const payload: any = { classification: data[0]?.classification || "Bulk", risk_score: Math.max(...data.map(d=>d.risk_score)), bulk: data, textPreview: texts[0]?.slice(0,200) };
        window.dispatchEvent(new CustomEvent("forensic:scan-complete", { detail: payload }));
        localStorage.setItem("forensic_last_scan", JSON.stringify(payload));
      } catch {}
    } catch(e){ setError(parseApiError(e)); }
    finally{ setLoading(false); }
  };

  const hasResult    = mode === "email" ? !!emailRes : mode==="url" ? !!urlRes : !!bulkRes;
  const risk         = mode === "email" ? emailRes?.risk_score ?? 0 : mode==="url" ? urlRes?.risk_score ?? 0 : (bulkRes ? Math.max(...bulkRes.map(r=>r.risk_score)) : 0);
  const classification = mode === "email" ? emailRes?.classification : mode==="url" ? urlRes?.status : (bulkRes ? bulkRes[0]?.classification : undefined);
  const cf           = classification ? clsf(classification) : null;
  const hops         = emailRes?.forensics?.header_forensics?.hops ?? [];

  // Dual Geolocation Resolution
  const serverGeo = emailRes?.geolocation
    || emailRes?.forensics?.origin_geolocation
    || emailRes?.forensics?.header_forensics?.originating_geo
    || urlRes?.geolocation;

  const senderGeo = emailRes?.sender_geolocation
    || emailRes?.forensics?.sender_geolocation
    || urlRes?.sender_geolocation;

  // Check if geolocation appears synthetic/unverified
  const isSyntheticGeo = Boolean(
    serverGeo && (serverGeo.country === "Unknown" || serverGeo.ip === "Unknown" || serverGeo.verification_source === undefined)
    && !hops.length
  );

  // Check Discrepancy between sender and server
  const isGeographicDiscrepancy = Boolean(
    senderGeo?.country_code && serverGeo?.country_code &&
    senderGeo.country_code !== "UN" && serverGeo.country_code !== "UN" &&
    senderGeo.country_code !== serverGeo.country_code
  );

  // Build Map Points (Sender + Server + Hops)
  const mapPoints: GeoPoint[] = (() => {
    const pts: GeoPoint[] = [];
    const seen = new Set<string>();

    // 1. Sender Point (Purple)
    if (senderGeo?.latitude && senderGeo?.longitude && senderGeo.latitude !== 0) {
      const key = `sender_${senderGeo.latitude.toFixed(2)},${senderGeo.longitude.toFixed(2)}`;
      seen.add(key);
      pts.push({
        lat: senderGeo.latitude,
        lng: senderGeo.longitude,
        label: "Sender Identity",
        pointType: "sender",
        city: senderGeo.city,
        country: senderGeo.country,
        ip: senderGeo.ip,
        isp: senderGeo.isp,
        org: senderGeo.org || (emailRes?.sender ? emailRes.sender : undefined),
        isOrigin: false,
        isSynthetic: false,
      });
    }

    // 2. Server Origin Point (Red)
    if (serverGeo?.latitude && serverGeo?.longitude && serverGeo.latitude !== 0) {
      pts.push({
        lat: serverGeo.latitude,
        lng: serverGeo.longitude,
        label: "Transmission Server",
        pointType: "server",
        city: serverGeo.city,
        country: serverGeo.country,
        ip: serverGeo.ip,
        isp: serverGeo.isp,
        org: serverGeo.org || "Mail Gateway Server",
        isOrigin: true,
        isSynthetic: isSyntheticGeo,
      });
    }

    // 3. Relay Hops (Cyan)
    hops.forEach((h, i) => {
      if (h.geo?.latitude && h.geo?.longitude && h.geo.latitude !== 0) {
        const coordKey = `${h.geo.latitude.toFixed(2)},${h.geo.longitude.toFixed(2)}`;
        if (!seen.has(coordKey)) {
          seen.add(coordKey);
          pts.push({
            lat: h.geo.latitude,
            lng: h.geo.longitude,
            label: `Relay Hop ${i + 1}`,
            pointType: "hop",
            city: h.geo.city,
            country: h.geo.country,
            ip: h.ip || h.geo.ip,
            isp: h.geo.isp,
            isOrigin: false,
            isSynthetic: isSyntheticGeo,
          });
        }
      }
    });

    return pts;
  })();

  const TABS = [
    { id: "overview", label: "Verdict",      icon: Shield     },
    { id: "geo",      label: "Dual Geolocation", icon: MapPin },
    { id: "graph",    label: "Attribution",  icon: Radio      },
    { id: "bec",      label: "BEC / Fraud",  icon: DollarSign },
    { id: "hashes",   label: "File Hashes",  icon: Hash       },
    { id: "intel",    label: "Threat Intel", icon: Eye        },
    { id: "mitre",    label: "MITRE",        icon: Cpu        },
  ] as const;

  return (
    <div className="space-y-5 animate-slide-up">

      {/* ── Page header ── */}
      <div className="flex items-start justify-between">
        <div>
          <h2 className="font-orbitron text-lg font-bold text-white tracking-wide">THREAT ANALYZER</h2>
          <p className="font-code text-[10px] text-slate-500 mt-1 tracking-wider">AI DUAL-GEOLOCATION & EMAIL FORENSICS SOC PLATFORM</p>
        </div>
        {hasResult && (
          <button onClick={clear} className="btn-danger">
            <RefreshCw className="w-3.5 h-3.5" />
            NEW SCAN
          </button>
        )}
      </div>

      {/* Mode — segmented, not pills */}
      <div className="inline-flex p-1 rounded-full border w-fit" style={{ background: "var(--panel-soft)", borderColor: "var(--border)" }}>
        {[
          { id: "email", label: "Email", icon: FileText },
          { id: "url", label: "URL", icon: Globe },
          { id: "bulk", label: "Bulk", icon: Copy },
        ].map(m => {
          const Icon = m.icon as any;
          const active = mode === m.id;
          return (
            <button key={m.id}
              onClick={() => { setMode(m.id as any); setError(null); }}
              className={`flex items-center gap-1.5 px-4 py-1.5 rounded-full text-[13px] font-medium transition ${active ? "bg-white text-slate-900 shadow-sm border border-slate-200" : "text-slate-500 hover:text-slate-700"}`}>
              <Icon className="w-3.5 h-3.5" />
              {m.label}
            </button>
          );
        })}
      </div>

      {/* Input — clear hierarchy, not card-everywhere */}
      {!hasResult && (
        <div className="panel rounded-xl p-6 space-y-4">
          <div>
            <h3 className="text-[14px] font-semibold" style={{ color: "var(--text)" }}>
              {mode === "email" ? "Paste email to analyze" : mode === "url" ? "Check a link" : "Bulk analysis"}
            </h3>
            <p className="text-[13px] mt-1 leading-5" style={{ color: "var(--muted)" }}>
              {mode === "email" ? "Supports raw RFC 5322 headers or plain body — paste the full source for deepest forensics." : mode === "url" ? "We’ll check DNS, WHOIS, SSL, VirusTotal and typosquatting." : "Up to 20 emails — separate each with a line containing ---"}
            </p>
          </div>

          {mode === "email" ? (
            <div className="space-y-3">
              <textarea
                value={text}
                onChange={e => setText(e.target.value)}
                placeholder={"Paste email — headers help (Subject, From, Received) but plain body also works.\n\nExample:\nSubject: Action required — verify account\nFrom: support@paypal.com\n\nDear customer, your account needs verification..."}
                rows={7}
                className="w-full rounded-lg px-3.5 py-3 text-[13px] leading-6 resize-none focus:outline-none focus:ring-1"
                style={{ background: "var(--panel)", border: "1px solid var(--border)", color: "var(--text)" }}
              />
              <div className="flex items-center justify-between pt-2">
                <p className="text-[12px]" style={{ color: "var(--faint)" }}>{text.length ? `${text.length} characters` : "Awaiting input — paste headers + body for full trace"}</p>
                <button onClick={scanEmail} disabled={loading || !text.trim()} className="btn-primary">
                  {loading ? <><RefreshCw className="w-4 h-4 animate-spin" /> Scanning…</> : <>Analyze email</>}
                </button>
              </div>
            </div>
          ) : mode === "url" ? (
            <div className="flex gap-3 items-start">
              <div className="flex-grow relative">
                <Link className="absolute left-3 top-[13px] w-4 h-4" style={{ color: "var(--faint)" }} />
                <input
                  value={url}
                  onChange={e => setUrl(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && scanUrl()}
                  placeholder="https://example.com/login — we’ll check domain age, SSL and reputation"
                  className="w-full rounded-lg pl-9 pr-3 py-2.5 text-[13px] focus:outline-none focus:ring-1"
                  style={{ background: "var(--panel)", border: "1px solid var(--border)", color: "var(--text)" }}
                />
                <p className="text-[11px] mt-1.5" style={{ color: "var(--faint)" }}>Press Enter to check. We never fetch the page content.</p>
              </div>
              <button onClick={scanUrl} disabled={loading} className="btn-primary flex-shrink-0">
                {loading ? <><RefreshCw className="w-4 h-4 animate-spin" /> Checking…</> : <>Check link</>}
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              <textarea
                value={bulkText}
                onChange={e=>setBulkText(e.target.value)}
                placeholder={"Paste up to 20 emails — separate each with a line that is just ---\n\nHello team, meeting tomorrow at 10am…\n---\nSubject: Verify your account\nFrom: support@paypal.com\n\nPlease verify..."}
                rows={7}
                className="w-full rounded-lg px-3.5 py-3 text-[13px] leading-6 resize-none focus:outline-none focus:ring-1"
                style={{ background: "var(--panel)", border: "1px solid var(--border)", color: "var(--text)" }}
              />
              <div className="flex items-center justify-between pt-1">
                <span className="text-[12px]" style={{ color: "var(--faint)" }}>{bulkText.split("\n---\n").filter(s=>s.trim()).length || 0} / 20 · separate with ---</span>
                <button onClick={scanBulk} disabled={loading || !bulkText.trim()} className="btn-primary">
                  {loading ? <><RefreshCw className="w-4 h-4 animate-spin" /> Scanning…</> : <>Run bulk check</>}
                </button>
              </div>
            </div>
          )}

          {error && (
            <div className="flex gap-2.5 p-3 rounded-lg border" style={{ background: "#fef2f2", borderColor: "#fecaca" }}>
              <AlertCircle className="w-4 h-4 text-red-600 flex-shrink-0 mt-0.5" />
              <span className="text-[13px] leading-5 text-red-700">{error}</span>
            </div>
          )}
        </div>
      )}

      {/* Loading — restrained */}
      {loading && (
        <div className="panel rounded-xl p-8 flex flex-col items-center gap-4">
          <div className="w-8 h-8 rounded-full border-2 animate-spin" style={{ borderColor: "var(--border)", borderTopColor: "var(--text)" }} />
          <div className="text-center">
            <p className="text-[13px] font-medium" style={{ color: "var(--text)" }}>Analyzing…</p>
            <p className="text-[12px] mt-1" style={{ color: "var(--muted)" }}>Checking indicators, reputation and routing</p>
          </div>
        </div>
      )}

      {/* ═══════════ RESULTS ═══════════ */}
      {mode === "bulk" && bulkRes && !loading && (
        <div className="space-y-4 animate-slide-up">
          <div className="panel rounded-xl p-5">
            <h3 className="font-orbitron text-sm font-bold text-white flex items-center gap-2"><Copy className="w-4 h-4 text-cyan-400" /> BULK RESULTS — {bulkRes.length} EMAILS</h3>
            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-xs font-code">
                <thead><tr className="border-b border-white/10 text-slate-500 text-[10px]"><th className="p-2 text-left">#</th><th className="p-2 text-left">CLASS</th><th className="p-2 text-left">RISK</th><th className="p-2 text-left">CONF</th><th className="p-2 text-left">PREVIEW</th></tr></thead>
                <tbody className="divide-y divide-white/5">
                  {bulkRes.map((r,i)=>(
                    <tr key={r.id||i} className="hover:bg-white/[0.02]">
                      <td className="p-2 text-slate-500">{i+1}</td>
                      <td className="p-2"><span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${r.classification==='Phishing'?'bg-red-500/10 border-red-500/20 text-red-400': r.classification==='Suspicious'?'bg-amber-500/10 border-amber-500/20 text-amber-400':'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'}`}>{r.classification}</span></td>
                      <td className="p-2 text-white">{r.risk_score.toFixed(0)}</td>
                      <td className="p-2 text-slate-400">{r.confidence_score.toFixed(0)}%</td>
                      <td className="p-2 text-slate-300 truncate max-w-[300px]">{r.explanation.slice(0,90)}...</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <button onClick={clear} className="btn-danger">NEW BULK SCAN</button>
            <button onClick={async()=>{
              const { API_URL } = await import("../config");
              const token = (()=>{try{return localStorage.getItem('forensic_jwt')}catch{return null}})();
              const url = API_URL ? `${API_URL}/api/history/export?limit=100` : `/api/history/export?limit=100`;
              const res = await fetch(url, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
              if(!res.ok) throw new Error(`HTTP ${res.status}`);
              const blob = await res.blob();
              const a=document.createElement("a");
              a.href=URL.createObjectURL(blob);
              a.download="scan_history.csv";
              document.body.appendChild(a); a.click(); a.remove();
              URL.revokeObjectURL(a.href);
            }} className="btn-primary"><Download className="w-3.5 h-3.5"/> EXPORT CSV</button>
          </div>
        </div>
      )}
      {hasResult && !loading && mode !== "bulk" && (
        <div ref={reportRef} className="space-y-4 animate-slide-up">

          {/* Verdict — restrained left accent */}
          <div className="panel rounded-xl p-5 flex flex-wrap items-start gap-4" style={{ borderLeft: `3px solid ${cf?.col || "#e5e7eb"}` }}>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg flex items-center justify-center text-[13px] font-semibold flex-shrink-0" style={{ background: cf?.label==="PHISHING" ? "#fef2f2" : cf?.label==="SUSPICIOUS" ? "#fffbeb" : "#ecfdf5", color: cf?.label==="PHISHING" ? "#991b1b" : cf?.label==="SUSPICIOUS" ? "#92400e" : "#065f46", border: `1px solid ${cf?.label==="PHISHING" ? "#fecaca" : cf?.label==="SUSPICIOUS" ? "#fde68a" : "#a7f3d0"}` }}>
                {Math.round(risk)}
              </div>
              <div>
                <div className="text-[11px] font-medium tracking-wide" style={{ color: "var(--faint)" }}>Verdict</div>
                <div className="text-[15px] font-semibold -mt-0.5" style={{ color: "var(--text)" }}>{cf?.label}</div>
              </div>
            </div>
            <div className="text-[12px] leading-5 min-w-0 flex-1" style={{ color: "var(--muted)" }}>
              Risk <span className="font-medium" style={{ color: "var(--text)" }}>{Math.round(risk)}/100</span> · Confidence <span className="font-medium" style={{ color: "var(--text)" }}>{mode === "email" ? `${(emailRes?.confidence_score ?? 0).toFixed(0)}%` : `${(urlRes?.risk_score ?? 0).toFixed(0)}%`}</span>
              {emailRes?.sender && <div className="text-[11px] mt-1 truncate" style={{ color: "var(--faint)" }}>From: {emailRes.sender}</div>}
            </div>

            {/* Quick Geo Badges */}
            <div className="flex flex-col sm:flex-row gap-3 flex-shrink-0">
              {senderGeo && (
                <div className="p-2.5 rounded-lg border border-purple-500/20 bg-purple-500/5 text-right">
                  <p className="font-code text-[8px] text-purple-400 font-bold tracking-widest">👤 SENDER IDENTITY</p>
                  <p className="font-code text-xs text-white font-bold mt-0.5">{senderGeo.city}, {senderGeo.country}</p>
                </div>
              )}
              {serverGeo && (
                <div className="p-2.5 rounded-lg border border-red-500/20 bg-red-500/5 text-right">
                  <p className="font-code text-[8px] text-red-400 font-bold tracking-widest">🖥️ SERVER ORIGIN</p>
                  <p className="font-code text-xs text-white font-bold mt-0.5">{serverGeo.city}, {serverGeo.country}</p>
                  <p className="font-code text-[9px] text-cyan-400">{serverGeo.ip}</p>
                </div>
              )}
            </div>

            {emailRes?.email_auth_results && (
              <div className="flex gap-2 flex-shrink-0 flex-wrap">
                {(["spf","dkim","dmarc"] as const).map(k => {
                  const pass = emailRes.email_auth_results![k] === "pass";
                  return (
                    <div key={k} className={`px-2.5 py-1 rounded-md border font-code text-[9px] font-bold
                      ${pass ? "border-emerald-500/25 bg-emerald-500/8 text-emerald-400" : "border-red-500/25 bg-red-500/8 text-red-400"}`}>
                      {k.toUpperCase()} {pass ? "✓" : "✗"}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Tabs */}
          <div className="panel rounded-xl overflow-hidden">
            <div className="flex gap-1 p-2 border-b border-white/[0.05] overflow-x-auto">
              {TABS.map(t => {
                const Icon = t.icon;
                const active = tab === t.id;
                return (
                  <button key={t.id} onClick={() => setTab(t.id)}
                    className={`soc-tab flex items-center gap-1.5 ${active ? "soc-tab-active" : "soc-tab-inactive"}`}>
                    <Icon className="w-3 h-3" />
                    {t.label}
                  </button>
                );
              })}
            </div>

            <div className="p-5">

              {/* ── VERDICT ── */}
              {tab === "overview" && (
                <div className="space-y-4 animate-slide-up">
                  <div className="data-cell rounded-lg">
                    <p className="font-code text-[9px] text-slate-500 tracking-widest mb-2">AI THREAT ANALYSIS</p>
                    <p className="font-code text-[11px] text-slate-300 leading-relaxed">
                      {mode === "email" ? emailRes?.explanation : urlRes?.advice}
                    </p>
                  </div>

                  {/* Discrepancy alert on Overview */}
                  {isGeographicDiscrepancy && (
                    <div className="p-3.5 rounded-lg border border-amber-500/25 bg-amber-500/8 flex items-start gap-3">
                      <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
                      <div>
                        <p className="font-code text-xs font-bold text-amber-300">GEOGRAPHIC SPOOFING ANOMALY DETECTED</p>
                        <p className="font-code text-[10px] text-slate-300 mt-0.5">
                          Sender identity claims to be in <span className="text-purple-300 font-bold">{senderGeo?.country} ({senderGeo?.city})</span>, 
                          but the email was actually transmitted from mail infrastructure in <span className="text-red-300 font-bold">{serverGeo?.country} ({serverGeo?.city})</span>.
                        </p>
                      </div>
                    </div>
                  )}

                  {emailRes?.detected_indicators && Object.keys(emailRes.detected_indicators).some(k => emailRes.detected_indicators[k]) && (
                    <div>
                      <p className="font-code text-[9px] text-slate-500 tracking-widest mb-2">DETECTED INDICATORS</p>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        {Object.entries(emailRes.detected_indicators).filter(([,v]) => v).map(([k]) => (
                          <div key={k} className="flex items-center gap-2.5 data-cell rounded-lg">
                            <AlertTriangle className="w-3.5 h-3.5 text-amber-400 flex-shrink-0" />
                            <span className="font-code text-[10px] text-slate-300">{k.replace(/_/g," ")}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {emailRes?.forensics?.forensic_flags && emailRes.forensics.forensic_flags.length > 0 && (
                    <div>
                      <p className="font-code text-[9px] text-slate-500 tracking-widest mb-2">FORENSIC FLAGS</p>
                      <div className="space-y-1.5">
                        {emailRes.forensics.forensic_flags.map((flag, i) => (
                          <div key={i} className="flex items-start gap-2.5 p-2.5 rounded-lg bg-red-500/5 border border-red-500/12">
                            <div className="w-1.5 h-1.5 rounded-full bg-red-400 mt-1 flex-shrink-0" />
                            <span className="font-code text-[10px] text-slate-300">{flag}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {urlRes?.reasons && urlRes.reasons.length > 0 && (
                    <div className="space-y-1.5">
                      {urlRes.reasons.map((r, i) => (
                        <div key={i} className="flex items-start gap-2.5 p-2.5 rounded-lg bg-amber-500/5 border border-amber-500/12">
                          <ChevronRight className="w-3.5 h-3.5 text-amber-400 flex-shrink-0 mt-0.5" />
                          <span className="font-code text-[10px] text-slate-300">{r}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* ── DUAL GEOLOCATION TAB ── */}
              {tab === "geo" && (
                <div className="space-y-5 animate-slide-up">

                  {/* Discrepancy Banner */}
                  {isGeographicDiscrepancy ? (
                    <div className="p-4 rounded-xl border border-red-500/30 bg-red-500/10 flex items-start gap-3.5">
                      <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5 animate-pulse" />
                      <div>
                        <p className="font-orbitron text-xs font-bold text-red-400 tracking-wide">
                          CRITICAL ROUTE ANOMALY: SENDER IDENTITY VS SERVER MISMATCH
                        </p>
                        <p className="font-code text-[11px] text-slate-200 mt-1 leading-relaxed">
                          Sender identity claims location in <span className="text-purple-300 font-bold underline">{senderGeo?.city}, {senderGeo?.country}</span> ({senderGeo?.org || "Corporate Domain"}), 
                          but the email was physically dispatched from <span className="text-red-300 font-bold underline">{serverGeo?.city}, {serverGeo?.country}</span> (IP: {serverGeo?.ip}). 
                          This is a high-confidence indicator of email spoofing or unauthorized relay usage.
                        </p>
                      </div>
                    </div>
                  ) : (
                    <div className="p-3.5 rounded-xl border border-emerald-500/20 bg-emerald-500/5 flex items-center gap-3">
                      <UserCheck className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                      <p className="font-code text-[10px] text-emerald-300">
                        Sender domain identity coordinates and server gateway transmission path successfully resolved.
                      </p>
                    </div>
                  )}

                  {/* Dual Comparison Cards */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

                    {/* SENDER CARD */}
                    <div className="p-4 rounded-xl border border-purple-500/25 bg-purple-950/15 space-y-3">
                      <div className="flex items-center justify-between pb-2 border-b border-purple-500/20">
                        <div className="flex items-center gap-2">
                          <div className="w-3 h-3 rounded-full bg-purple-400 shadow-[0_0_8px_#a855f7]" />
                          <span className="font-orbitron text-xs font-bold text-purple-300 tracking-wider">1. SENDER IDENTITY ORIGIN</span>
                        </div>
                        <span className="font-code text-[9px] px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                          {senderGeo?.country_code || "IDENTITY"}
                        </span>
                      </div>

                      <div className="grid grid-cols-2 gap-2 text-[10px] font-code">
                        <div className="data-cell rounded-lg">
                          <p className="text-[8px] text-slate-500 tracking-widest">CLAIMED SENDER</p>
                          <p className="text-white font-bold mt-0.5 truncate" title={emailRes?.sender || "Sender Domain"}>
                            {emailRes?.sender || "Direct Input"}
                          </p>
                        </div>
                        <div className="data-cell rounded-lg">
                          <p className="text-[8px] text-slate-500 tracking-widest">IDENTITY LOCATION</p>
                          <p className="text-purple-300 font-bold mt-0.5 truncate">
                            {senderGeo?.city || "Unknown"}, {senderGeo?.country || "Unknown"}
                          </p>
                        </div>
                        <div className="data-cell rounded-lg">
                          <p className="text-[8px] text-slate-500 tracking-widest">ORGANIZATION / DOMAIN</p>
                          <p className="text-slate-300 mt-0.5 truncate">{senderGeo?.org || senderGeo?.isp || "Corporate Entity"}</p>
                        </div>
                        <div className="data-cell rounded-lg">
                          <p className="text-[8px] text-slate-500 tracking-widest">COORDINATES</p>
                          <p className="text-purple-400 font-bold mt-0.5">
                            {senderGeo?.latitude?.toFixed(4)}, {senderGeo?.longitude?.toFixed(4)}
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* SERVER CARD */}
                    <div className="p-4 rounded-xl border border-red-500/25 bg-red-950/15 space-y-3">
                      <div className="flex items-center justify-between pb-2 border-b border-red-500/20">
                        <div className="flex items-center gap-2">
                          <div className={`w-3 h-3 rounded-full ${serverGeo ? "bg-red-400 shadow-[0_0_8px_#ef4444]" : "bg-slate-600"}`} />
                          <span className="font-orbitron text-xs font-bold text-red-300 tracking-wider">2. TRANSMISSION INFRASTRUCTURE</span>
                        </div>
                        <span className="font-code text-[9px] px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30">
                          {serverGeo?.country_code || (serverGeo ? "VERIFIED" : "HEADER PENDING")}
                        </span>
                      </div>

                      {serverGeo ? (
                        <div className="grid grid-cols-2 gap-2 text-[10px] font-code">
                          <div className="data-cell rounded-lg">
                            <p className="text-[8px] text-slate-500 tracking-widest">ORIGIN SERVER IP</p>
                            <p className="text-cyan-400 font-bold mt-0.5 truncate">{serverGeo.ip}</p>
                          </div>
                          <div className="data-cell rounded-lg">
                            <p className="text-[8px] text-slate-500 tracking-widest">PHYSICAL LOCATION</p>
                            <p className="text-red-300 font-bold mt-0.5 truncate">
                              {serverGeo.city}, {serverGeo.country}
                            </p>
                          </div>
                          <div className="data-cell rounded-lg">
                            <p className="text-[8px] text-slate-500 tracking-widest">SERVER ISP / ASN</p>
                            <p className="text-slate-300 mt-0.5 truncate">{serverGeo.isp || serverGeo.asn || "Verified Gateway"}</p>
                          </div>
                          <div className="data-cell rounded-lg">
                            <p className="text-[8px] text-slate-500 tracking-widest">COORDINATES</p>
                            <p className="text-red-400 font-bold mt-0.5">
                              {serverGeo.latitude ? `${serverGeo.latitude.toFixed(4)}, ${serverGeo.longitude?.toFixed(4)}` : "Live IP Map"}
                            </p>
                          </div>
                        </div>
                      ) : (
                        <div className="p-3 rounded-lg border border-white/[0.06] bg-black/40 text-center font-code">
                          <p className="text-xs text-amber-300 font-bold">No Transmission IP in Raw Input</p>
                          <p className="text-[11px] mt-1 leading-relaxed" style={{ color: "var(--muted)" }}>
                            Paste full headers with <code style={{ background: "var(--panel-soft)", border: "1px solid var(--border)", padding: "1px 4px", borderRadius: 4 }}>Received:</code> lines to trace the relay path.
                          </p>
                        </div>
                      )}
                    </div>

                  </div>

                  {/* ── LEAFLET SATELLITE MAP (ALWAYS ACTIVE & INTERACTIVE) ── */}
                  <GeoMap points={mapPoints} height={440} />

                  {/* Relay Hop Path */}
                  {hops.length > 0 && (
                    <div className="space-y-2">
                      <p className="font-code text-[9px] text-slate-500 tracking-widest uppercase">
                        TRANSMISSION RELAY PATH — {hops.length} HOP{hops.length > 1 ? "S" : ""}
                      </p>
                      <div className="hop-line space-y-2 pl-6">
                        {hops.map((hop, i) => (
                          <div key={i} className="relative">
                            <div className="absolute -left-6 top-3 w-5 h-5 rounded-full bg-[#02040a] border-2 border-cyan-500/40 flex items-center justify-center">
                              <span className="font-code text-[7px] font-bold text-cyan-400">{hop.hop_number}</span>
                            </div>
                            <div className="data-cell rounded-lg space-y-1.5">
                              <div className="flex items-center justify-between">
                                <span className="font-code text-[9px] text-cyan-400 font-bold">RELAY HOP #{hop.hop_number}</span>
                                {hop.delay_seconds != null && <span className="font-code text-[8px] text-slate-600">+{hop.delay_seconds}s latency</span>}
                              </div>
                              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 font-code text-[9px]">
                                {hop.from_server && <p className="text-slate-400 truncate">FROM: <span className="text-white">{hop.from_server}</span></p>}
                                {hop.by_server   && <p className="text-slate-400 truncate">BY: <span className="text-white">{hop.by_server}</span></p>}
                                {hop.ip && <p className="text-slate-500">IP: <span className="text-cyan-400">{hop.ip}</span>{hop.geo?.city ? ` · ${hop.geo.city}, ${hop.geo.country}` : ""}</p>}
                                {hop.timestamp && <p className="text-slate-600">{hop.timestamp}</p>}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                </div>
              )}

              {/* ── ATTRIBUTION ── */}
              {tab === "graph" && (
                <div className="space-y-4 animate-slide-up">
                  {emailRes?.forensics?.attribution ? (
                    <>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        {[
                          { l: "ACTOR TYPE",   v: emailRes.forensics.attribution.probable_actor_type       },
                          { l: "INFRA TYPE",   v: emailRes.forensics.attribution.infrastructure_type       },
                          { l: "CONFIDENCE",   v: `${emailRes.forensics.attribution.attribution_confidence}%` },
                          { l: "CAMPAIGN",     v: emailRes.forensics.attribution.suspected_campaign || "UNCLASSIFIED" },
                          { l: "TOR NETWORK",  v: emailRes.forensics.attribution.tor_detected ? "YES ⚠" : "NO",        warn: emailRes.forensics.attribution.tor_detected       },
                          { l: "VPN / PROXY",  v: emailRes.forensics.attribution.vpn_or_proxy_detected ? "YES ⚠" : "NO", warn: emailRes.forensics.attribution.vpn_or_proxy_detected },
                        ].map(it => (
                          <div key={it.l} className="data-cell rounded-lg flex justify-between items-center">
                            <span className="font-code text-[9px] text-slate-500">{it.l}</span>
                            <span className={`font-code text-[10px] font-bold ${it.warn ? "text-amber-400" : "text-white"}`}>{it.v || "—"}</span>
                          </div>
                        ))}
                      </div>
                      {emailRes.forensics.attribution.threat_actor_indicators.length > 0 && (
                        <div className="space-y-1.5">
                          <p className="font-code text-[9px] text-slate-500 tracking-widest">THREAT ACTOR INDICATORS</p>
                          {emailRes.forensics.attribution.threat_actor_indicators.map((ind, i) => (
                            <div key={i} className="flex items-start gap-2.5 p-2.5 rounded-lg bg-amber-500/5 border border-amber-500/12">
                              <AlertTriangle className="w-3.5 h-3.5 text-amber-400 flex-shrink-0 mt-0.5" />
                              <span className="font-code text-[10px] text-slate-300">{ind}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </>
                  ) : (
                    <div className="text-center py-10 font-code text-[10px] text-slate-600">No attribution data available.</div>
                  )}
                </div>
              )}

              {/* ── BEC ── */}
              {tab === "bec" && (
                <div className="space-y-4 animate-slide-up">
                  {emailRes?.forensics?.bec_analysis ? (
                    <>
                      <div className={`p-4 rounded-xl ${emailRes.forensics.bec_analysis.is_bec_threat ? "panel-red" : "panel-green"} flex items-center gap-3`}>
                        <DollarSign className={`w-5 h-5 ${emailRes.forensics.bec_analysis.is_bec_threat ? "text-red-400" : "text-emerald-400"}`} />
                        <div>
                          <p className="font-code text-[9px] text-slate-500 tracking-widest">BEC THREAT STATUS</p>
                          <p className={`font-orbitron text-sm font-bold ${emailRes.forensics.bec_analysis.is_bec_threat ? "text-glow-red" : "text-glow-green"}`}>
                            {emailRes.forensics.bec_analysis.is_bec_threat ? "BUSINESS EMAIL COMPROMISE DETECTED" : "NO BEC INDICATORS FOUND"}
                          </p>
                        </div>
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        {[["ATTACK TYPE",emailRes.forensics.bec_analysis.bec_type],["URGENCY LEVEL",emailRes.forensics.bec_analysis.urgency_level]].map(([l,v]) => (
                          <div key={l} className="data-cell rounded-lg">
                            <p className="font-code text-[9px] text-slate-500">{l}</p>
                            <p className="font-code text-xs text-white font-bold mt-1">{v || "—"}</p>
                          </div>
                        ))}
                      </div>
                      {emailRes.forensics.bec_analysis.detected_patterns.length > 0 && (
                        <div className="space-y-1.5">
                          <p className="font-code text-[9px] text-slate-500 tracking-widest">SOCIAL ENGINEERING PATTERNS</p>
                          {emailRes.forensics.bec_analysis.detected_patterns.map((p, i) => (
                            <div key={i} className="flex items-start gap-2.5 p-2.5 rounded-lg bg-red-500/5 border border-red-500/12">
                              <div className="w-1.5 h-1.5 rounded-full bg-red-400 mt-1 flex-shrink-0" />
                              <span className="font-code text-[10px] text-slate-300">{p}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </>
                  ) : (
                    <div className="text-center py-10 font-code text-[10px] text-slate-600">No BEC analysis data available.</div>
                  )}
                </div>
              )}

              {/* ── HASHES ── */}
              {tab === "hashes" && (
                <div className="space-y-3 animate-slide-up">
                  {emailRes?.forensics?.attachment_forensics && emailRes.forensics.attachment_forensics.length > 0 ? (
                    emailRes.forensics.attachment_forensics.map((af, i) => (
                      <div key={i} className={`rounded-xl p-4 space-y-3 ${af.risk_level === "High" ? "panel-red" : af.risk_level === "Medium" ? "panel-amber" : "panel"}`}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2.5">
                            <FileText className="w-4 h-4 text-slate-400" />
                            <span className="font-code text-xs text-white font-bold">{af.filename}</span>
                            <span className={`px-2 py-0.5 rounded-md border font-code text-[8px] font-bold
                              ${af.risk_level === "High" ? "border-red-500/25 bg-red-500/8 text-red-400"
                              : af.risk_level === "Medium" ? "border-amber-500/25 bg-amber-500/8 text-amber-400"
                              : "border-emerald-500/25 bg-emerald-500/8 text-emerald-400"}`}>{af.risk_level.toUpperCase()}</span>
                          </div>
                          <span className="font-code text-[9px] text-slate-500">{(af.size_bytes / 1024).toFixed(1)} KB</span>
                        </div>
                        <div className="space-y-1.5">
                          {[["MD5",af.md5],["SHA1",af.sha1],["SHA256",af.sha256]].map(([l,v]) => (
                            <div key={l} className="flex items-center gap-3 p-2.5 rounded-lg bg-black/30 border border-white/[0.04]">
                              <span className="font-code text-[9px] text-slate-500 w-12 flex-shrink-0">{l}</span>
                              <span className="font-code text-[9px] text-white flex-grow truncate">{v || "—"}</span>
                              {v && (
                                <button onClick={() => copy(v as string, `${i}-${l}`)}
                                  className="p-1.5 rounded bg-white/[0.04] hover:bg-cyan-500/10 text-slate-500 hover:text-cyan-400 transition-all flex-shrink-0">
                                  {copied === `${i}-${l}` ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                                </button>
                              )}
                            </div>
                          ))}
                        </div>
                        {af.details && <p className="font-code text-[9px] text-slate-400">{af.details}</p>}
                      </div>
                    ))
                  ) : (
                    <div className="text-center py-10 text-[12px]" style={{ color: "var(--muted)" }}>No file hashes in this scan. Upload an <code style={{ background: "var(--panel-soft)", padding: "2px 6px", borderRadius: 6, border: "1px solid var(--border)" }}>.eml</code> with attachments to see hashes.</div>
                  )}
                </div>
              )}

              {/* ── INTEL ── */}
              {tab === "intel" && (
                <div className="space-y-4 animate-slide-up">
                  {emailRes?.llm_analysis ? (
                    <>
                      <div className="data-cell rounded-lg">
                        <p className="font-code text-[9px] text-slate-500 tracking-widest mb-2">AI DANGER ASSESSMENT</p>
                        <p className="font-code text-[11px] text-slate-300 leading-relaxed">{emailRes.llm_analysis.danger_explanation}</p>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {[
                          { l: "SOCIAL ENGINEERING TACTICS", items: emailRes.llm_analysis.social_engineering_techniques, bg: "bg-amber-500/5 border-amber-500/12" },
                          { l: "INDICATORS OF COMPROMISE",   items: emailRes.llm_analysis.indicators_of_compromise,      bg: "bg-red-500/5 border-red-500/12"   },
                          { l: "SAFETY RECOMMENDATIONS",     items: emailRes.llm_analysis.safety_recommendations,        bg: "bg-cyan-500/5 border-cyan-500/12" },
                        ].map(s => s.items?.length > 0 && (
                          <div key={s.l} className="space-y-2">
                            <p className="font-code text-[9px] text-slate-500 tracking-widest">{s.l}</p>
                            {s.items.map((item, i) => (
                              <div key={i} className={`p-2.5 rounded-lg border font-code text-[10px] text-slate-300 ${s.bg}`}>{item}</div>
                            ))}
                          </div>
                        ))}
                      </div>
                    </>
                  ) : (
                    <div className="text-center py-10 font-code text-[10px] text-slate-600">No threat intelligence data available.</div>
                  )}
                </div>
              )}

              {/* ── MITRE ── */}
              {tab === "mitre" && (
                <div className="space-y-3 animate-slide-up">
                  {emailRes?.llm_analysis?.mitre_mappings && emailRes.llm_analysis.mitre_mappings.length > 0 ? (
                    emailRes.llm_analysis.mitre_mappings.map((m, i) => (
                      <div key={i} className="data-cell rounded-lg space-y-2">
                        <div className="flex items-center gap-3">
                          <span className="px-2.5 py-1 rounded-md bg-purple-500/10 border border-purple-500/25 font-code text-[10px] font-bold text-purple-400">{m.id}</span>
                          <span className="font-code text-[11px] font-bold text-white">{m.name}</span>
                        </div>
                        {m.description && <p className="font-code text-[10px] text-slate-400 leading-relaxed">{m.description}</p>}
                      </div>
                    ))
                  ) : (
                    <div className="text-center py-10 font-code text-[10px] text-slate-600">No MITRE ATT&CK mappings available.</div>
                  )}
                </div>
              )}

            </div>
          </div>

          {/* Export */}
          <div className="flex justify-end">
            <button onClick={async () => {
              if (!reportRef.current) return;
              try {
                const { default: html2canvas } = await import("html2canvas");
                const { jsPDF } = await import("jspdf");
                const canvas = await html2canvas(reportRef.current, { backgroundColor: "#02040a", scale: 2 });
                const pdf = new jsPDF({ orientation: "portrait", format: "a4" });
                const img = canvas.toDataURL("image/png");
                const w = pdf.internal.pageSize.getWidth();
                const h = (canvas.height * w) / canvas.width;
                pdf.addImage(img, "PNG", 0, 0, w, Math.min(h, pdf.internal.pageSize.getHeight()));
                pdf.save(`forensic-report-${Date.now()}.pdf`);
              } catch(e) { console.error(e); }
            }} className="btn-primary">
              <Download className="w-3.5 h-3.5" />
              EXPORT PDF REPORT
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
