import axios, { AxiosError } from 'axios';

export const cleanApiUrl = (url: string) => (url ? url.trim().replace(/\/+$/, '') : '');

export const DEFAULT_PROD_URL = 'https://forensic-ai-2.onrender.com';
export const RAW_API_URL = cleanApiUrl(import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || '');
const isLocalEnv = typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' || window.location.hostname === '');
export const API_URL = RAW_API_URL || (isLocalEnv ? 'http://127.0.0.1:8080' : DEFAULT_PROD_URL);

/**
 * Dynamically resolves all candidate API URLs in order of priority:
 * 1. Default Production Backend (https://forensic-ai-2.onrender.com)
 * 2. Vite Build-time environment variable (VITE_API_URL)
 * 3. User override in localStorage (Settings tab)
 * 4. Same-origin fallback (only if not on a known static site host)
 */
export function getActiveApiUrls(): string[] {
  const candidates: string[] = [];
  const isHttps = typeof window !== 'undefined' && window.location.protocol === 'https:';
  const hostname = typeof window !== 'undefined' ? window.location.hostname : '';
  const isLocal = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '';

  const addCandidate = (url: string) => {
    const cleaned = cleanApiUrl(url);
    if (!cleaned) {
      if (!isLocal && (hostname.includes('forensic-ai-1') || hostname.includes('vercel.app') || hostname.includes('netlify.app'))) {
        return;
      }
      if (!candidates.includes('')) candidates.push('');
      return;
    }
    if (isHttps && cleaned.startsWith('http://')) {
      return;
    }
    if (!candidates.includes(cleaned)) {
      candidates.push(cleaned);
    }
  };

  // When running locally, strictly connect to http://127.0.0.1:8080 first
  if (isLocal) {
    addCandidate('http://127.0.0.1:8080');
    addCandidate('');
    if (RAW_API_URL) {
      addCandidate(RAW_API_URL);
    }
  } else {
    // When running in production (Vercel / Netlify / Render)
    if (RAW_API_URL) {
      addCandidate(RAW_API_URL);
    }
    addCandidate(DEFAULT_PROD_URL);
    addCandidate('');
  }

  // 3. User override in localStorage
  if (typeof window !== 'undefined') {
    try {
      const raw = localStorage.getItem('forensic_settings_v2');
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed.apiUrl && typeof parsed.apiUrl === 'string' && parsed.apiUrl.trim()) {
          addCandidate(parsed.apiUrl);
        }
      }
    } catch {}
  }

  return candidates;
}

export const API_URLS: string[] = getActiveApiUrls();

function getEndpointUrl(path: string, baseUrl: string) {
  const normalizedBase = baseUrl.replace(/\/$/, '');
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;

  if (!normalizedBase || normalizedBase === '/') {
    return normalizedPath;
  }

  return `${normalizedBase}${normalizedPath}`;
}

export function isOfflineError(error: unknown): boolean {
  if (!axios.isAxiosError(error)) {
    return true;
  }

  const axiosError = error as AxiosError;
  return !axiosError.response
    || axiosError.code === 'ECONNABORTED'
    || axiosError.code === 'ERR_NETWORK'
    || axiosError.code === 'ETIMEDOUT'
    || axiosError.message?.toLowerCase().includes('network');
}

export interface LocalPredictResponse {
  classification: string;
  confidence_score: number;
  risk_score: number;
  explanation: string;
  detected_indicators: Record<string, boolean>;
  highlighted_text: string;
  xai_keywords: Array<{ word: string; weight: number; type: string }>;
  id?: number;
  subject?: string;
  sender?: string;
  created_at?: string;
}

export function getOfflineEmailAnalysis(text: string, fileName?: string): LocalPredictResponse {
  const source = `${text || fileName || 'uploaded content'}`.toLowerCase();
  const suspiciousSignals = [
    /click/i,
    /urgent|immediately|act now|limited time/i,
    /verify|login|password|reset/i,
    /bank|invoice|pay/i,
    /free|winner|prize/i
  ];

  const matchedSignals = suspiciousSignals.filter((pattern) => pattern.test(source));
  const suspicious = matchedSignals.length >= 1;
  const classification = suspicious ? 'Suspicious' : 'Safe';
  const riskScore = suspicious ? 72 : 24;
  const confidence = suspicious ? 74 : 68;
  const explanation = suspicious
    ? 'The backend was unavailable, so this result uses a local heuristic scan. Common phishing cues such as urgency, credential requests, or payment pressure were detected.'
    : 'The backend was unavailable, so this result uses a local heuristic scan. No obvious phishing cues were detected in the supplied content.';

  return {
    classification,
    confidence_score: confidence,
    risk_score: riskScore,
    explanation,
    detected_indicators: {
      urgent_language: /urgent|immediately|act now|limited time/i.test(source),
      suspicious_urls: /http|https|login|verify/i.test(source),
      fake_login: /login|signin|verify/i.test(source),
      password_request: /password|reset/i.test(source),
      banking_scam: /bank|invoice|payment/i.test(source),
      financial_fraud: /pay|payment|invoice/i.test(source),
      crypto_scam: /crypto|wallet|coin/i.test(source),
      grammar_issues: false,
      spoofed_sender: false,
      dangerous_attachments: false
    },
    highlighted_text: text || fileName || 'Offline fallback analysis',
    xai_keywords: [
      { word: 'urgent', weight: 0.9, type: 'signal' },
      { word: 'password', weight: 0.85, type: 'signal' },
      { word: 'verify', weight: 0.8, type: 'signal' }
    ]
  };
}

export function getOfflineUrlAnalysis(url: string) {
  const lowered = url.toLowerCase();
  const suspicious = /login|signin|verify|secure|bank|pay|crypto|free/i.test(lowered);
  return {
    id: 0,
    url,
    domain: new URL(url).hostname.replace(/^www\./, ''),
    risk_score: suspicious ? 78 : 24,
    status: suspicious ? 'Suspicious' : 'Safe',
    reasons: suspicious
      ? ['The URL contains login-like or payment-related keywords.']
      : ['No obvious reputational risk cues were detected.'],
    threat_type: suspicious ? 'Phishing' : 'Low Risk',
    advice: suspicious
      ? 'Avoid entering credentials and verify the destination through a trusted channel.'
      : 'The URL looks benign based on the local heuristic check.',
    created_at: new Date().toISOString()
  };
}

function getAuthHeader(): Record<string, string> {
  try {
    const t = typeof window !== 'undefined' ? localStorage.getItem('forensic_jwt') : null;
    if (t && t !== 'undefined' && t !== 'null' && typeof t === 'string' && t.split('.').length === 3) {
      return { Authorization: `Bearer ${t.trim()}` };
    }
    return {};
  } catch { return {}; }
}

export async function apiRequest<T>(path: string, options: { method?: 'get' | 'post'; data?: any; headers?: Record<string, string>; timeout?: number } = {}): Promise<T> {
  const method = options.method ?? 'get';
  let lastError: unknown;
  const urlsToTry = getActiveApiUrls();

  for (const baseUrl of urlsToTry) {
    try {
      const response = await axios<T>({
        method,
        url: getEndpointUrl(path, baseUrl),
        data: options.data,
        headers: { ...getAuthHeader(), ...(options.headers || {}) },
        timeout: options.timeout ?? 15000
      });
      return response.data;
    } catch (error) {
      lastError = error;
      if (axios.isAxiosError(error) && error.response) {
        const status = error.response.status;
        if (status === 400 || status === 401 || status === 403 || status === 422) {
          throw error;
        }
      }
      // Continue to next candidate URL
    }
  }

  throw lastError ?? new Error('Unable to reach the security backend.');
}

export function parseApiError(error: any): string {
  if (axios.isAxiosError(error)) {
    const axiosError = error as AxiosError;

    if (!axiosError.response) {
      if (axiosError.code === 'ECONNABORTED' || axiosError.message?.toLowerCase().includes('timeout')) {
        return 'Request Timeout: The request to the security engine timed out. Please try again.';
      }
      return 'Network Connectivity Error: The security server is currently unreachable. Check your backend URL or internet connection.';
    }

    const status = axiosError.response.status;
    const data = axiosError.response.data as any;
    
    let serverMessage = '';
    if (typeof data?.detail === 'string') {
      serverMessage = data.detail;
    } else if (Array.isArray(data?.detail)) {
      serverMessage = data.detail.map((d: any) => (typeof d === 'string' ? d : d.msg || JSON.stringify(d))).join(', ');
    } else if (typeof data?.message === 'string') {
      serverMessage = data.message;
    } else if (data && typeof data === 'object') {
      try {
        serverMessage = Object.entries(data).map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join('; ');
      } catch {
        serverMessage = String(data);
      }
    }

    if (status === 401 || status === 403) {
      return `Access Denied (${status}): ${serverMessage || 'Authentication required.'}`;
    }
    if (status === 404) {
      return `Not Found (404): ${serverMessage || 'The requested endpoint does not exist.'}`;
    }
    if (status === 429) {
      return `Rate Limit Exceeded (429): You have sent too many requests. Please wait a moment.`;
    }
    if (status >= 500) {
      return `Internal Server Error (${status}): ${serverMessage || 'The server encountered an unexpected exception.'}`;
    }

    return serverMessage || `API Error (${status}): ${axiosError.message}`;
  }

  if (error instanceof Error) {
    return error.message;
  }

  if (typeof error === 'object' && error !== null) {
    try { return JSON.stringify(error); } catch {}
  }

  return String(error || 'An unexpected communication error occurred.');
}

export async function executeWithRetry<T>(
  fn: () => Promise<T>,
  retries = 2,
  delay = 1000
): Promise<T> {
  try {
    return await fn();
  } catch (error) {
    if (retries > 0 && (isOfflineError(error) || (axios.isAxiosError(error) && (!error.response || error.response.status >= 500)))) {
      console.warn(`API call failed. Retrying in ${delay}ms... (${retries} retries left)`);
      await new Promise(resolve => setTimeout(resolve, delay));
      return executeWithRetry(fn, retries - 1, delay * 2);
    }
    throw error;
  }
}
