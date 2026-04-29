import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Globe,
  AlertCircle,
  CheckCircle,
  AlertTriangle,
  Loader2,
  Search,
  Shield,
  Lock,
  Database,
  Eye,
  Play,
  XCircle,
  Monitor,
  Sparkles,
  BarChart3,
  TrendingUp,
  Link2,
  Clock3,
  Server,
  FileText,
  RefreshCw,
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useLanguage } from '../contexts/LanguageContext';
import { apiUrl } from '../config/api';

type LayerResult = {
  passed?: boolean;
  issues?: string[];
  found?: boolean;
  verified?: boolean;
  threat_level?: string;
  message?: string;
  source?: string;
  threat_type?: string;
  domain_matches?: number;
  reputation_score?: number;
  indicators?: string[];
  threat_score?: number;
  [key: string]: any;
};

type ScanResult = {
  status: 'clean' | 'malicious' | 'suspicious';
  threat_score: number;
  details: {
    url: string;
    layers: {
      layer1_format: LayerResult;
      layer2_phishtank: LayerResult;
      layer3_reputation: LayerResult;
      layer4_content: LayerResult;
    };
    overall_threat_score: number;
    scan_timestamp: string;
  };
};

type DynamicProcess = {
  pid?: number;
  name: string;
  action?: string;
  suspicious?: boolean;
  riskLevel?: string;
  cpu?: number | null;
};

type DynamicNetwork = {
  protocol?: string;
  destination?: string;
  port?: number;
  suspicious?: boolean;
  classification?: string;
};

type DynamicFile = {
  path?: string;
  action?: string;
  suspicious?: boolean;
};

type DynamicRegistry = {
  key?: string;
  action?: string;
  suspicious?: boolean;
};

type DynamicResult = {
  verdict: 'clean' | 'malicious' | 'suspicious';
  threatScore: number;
  duration: number;
  processes: DynamicProcess[];
  network: DynamicNetwork[];
  files: DynamicFile[];
  registry: DynamicRegistry[];
  summary: string[];
  targetUrl?: string;
  scanMode?: string;
};

type BrowserDynamicRequest = {
  method: string;
  url: string;
  resourceType?: string;
};

type BrowserDynamicResponse = {
  url: string;
  status: number;
  contentType?: string;
};

type BrowserDynamicScreenshot = {
  label: string;
  image: string;
};

type BrowserDynamicFormItem = {
  action?: string;
  method?: string;
  inputCount?: number;
  passwordFields?: number;
};

type BrowserDynamicResult = {
  verdict: 'clean' | 'malicious' | 'suspicious';
  threatScore: number;
  duration: number;
  targetUrl?: string;
  finalUrl?: string;
  finalTitle?: string;
  requestCount: number;
  responseCount: number;
  requests: BrowserDynamicRequest[];
  responses: BrowserDynamicResponse[];
  redirectChain: string[];
  consoleMessages: { type: string; text: string }[];
  downloads: { url: string; suggestedFilename: string }[];
  dialogs: { type: string; message: string }[];
  pageErrors: string[];
  outgoingHosts: string[];
  forms: {
    count: number;
    passwordFormCount: number;
    items: BrowserDynamicFormItem[];
  };
  indicators: string[];
  screenshots: BrowserDynamicScreenshot[];
  summary: string[];
};

type DynamicPollResponse = {
  job_id: string;
  status: 'running' | 'done' | 'error';
  step: string;
  progress: number;
  filename: string;
  result?: DynamicResult;
  error?: string;
  finished_at?: string | null;
  scan_mode?: string;
  target_url?: string;
  static_status?: string;
  static_threat_score?: number;
};

type ThreatFeedStats = {
  total_threat_urls: number;
  verified_threat_urls: number;
  unique_domains: number;
  phishtank_entries: number;
  scan_totals: {
    total: number;
    malicious: number;
    suspicious: number;
    clean: number;
  };
};

type UrlDetailHeader = {
  name: string;
  value: string;
};

type UrlTechnicalDetails = {
  url: string;
  categories: string[];
  history: {
    scan_count: number;
    first_submission?: string | null;
    last_submission?: string | null;
    last_analysis?: string | null;
    feed_first_seen?: string | null;
    domain_feed_matches?: number;
  };
  domain_info: {
    available?: boolean;
    error?: string;
    host?: string;
    registered_domain?: string;
    registrar?: string | null;
    registry_country?: string | null;
    abuse_contact?: string | null;
    created_at?: string | null;
    updated_at?: string | null;
    expires_at?: string | null;
    dns_addresses?: string[];
    nameservers?: string[];
    rdap_error?: string | null;
    rdap_source?: string;
  };
  http_response: {
    fetch_allowed?: boolean;
    error?: string;
    final_url?: string;
    serving_ip_address?: string | null;
    resolved_ips?: string[];
    status_code?: number | null;
    body_length?: number | null;
    body_sha256?: string | null;
    headers?: UrlDetailHeader[];
    page_title?: string | null;
    redirect_chain?: { status_code: number; location: string }[];
    outgoing_links?: string[];
    redirected?: boolean;
    body_truncated?: boolean;
    fetched_at?: string | null;
    tls?: {
      available?: boolean;
      error?: string;
      subject?: string;
      issuer?: string;
      valid_from?: string | null;
      valid_to?: string | null;
      serial_number?: string | null;
      subject_alt_names?: string[];
    };
  };
  static_context: {
    status?: string;
    threat_score?: number;
    scan_timestamp?: string | null;
    match_type?: string | null;
    source?: string | null;
    verified?: boolean;
  };
};

const pickRandom = (items: string[]): string => {
  if (!items.length) return '';
  return items[Math.floor(Math.random() * items.length)];
};

const hasUrlScheme = (value: string) => /^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(value);

const normalizeUrlInput = (value: string): string => {
  const trimmed = value.trim();
  if (!trimmed) return '';

  if (hasUrlScheme(trimmed)) {
    return trimmed;
  }

  return `https://${trimmed}`;
};

const formatTimestamp = (value?: string | null): string => {
  if (!value) return 'N/A';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
};

const formatBytes = (value?: number | null): string => {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return 'N/A';
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(2)} KB`;
  return `${(value / (1024 * 1024)).toFixed(2)} MB`;
};

const formatJoinedList = (items?: string[] | null): string => {
  if (!items || items.length === 0) return 'N/A';
  return items.join(', ');
};

const OverviewRow = ({ label, value }: { label: string; value: string }) => (
  <div className="grid grid-cols-[220px_minmax(0,1fr)] gap-4 border-t border-slate-700/70 py-3 first:border-t-0 first:pt-0">
    <p className="text-sm font-semibold text-slate-200">{label}</p>
    <p className="break-words text-sm text-slate-300">{value}</p>
  </div>
);

export function URLScannerView() {
  const { user, token, signOut } = useAuth();
  const { translateText } = useLanguage();
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [previousResult, setPreviousResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [currentLayer, setCurrentLayer] = useState(0);
  const [feedStats, setFeedStats] = useState<ThreatFeedStats | null>(null);
  const [hookFact, setHookFact] = useState('Security fact: every URL is checked through four independent risk layers.');
  const [dynState, setDynState] = useState<'idle' | 'running' | 'done' | 'error'>('idle');
  const [dynStep, setDynStep] = useState('');
  const [dynProgress, setDynProgress] = useState(0);
  const [dynResult, setDynResult] = useState<DynamicResult | null>(null);
  const [dynError, setDynError] = useState<string | null>(null);
  const [dynJobId, setDynJobId] = useState<string | null>(null);
  const [dynCancelling, setDynCancelling] = useState(false);
  const [browserDynState, setBrowserDynState] = useState<'idle' | 'running' | 'done' | 'error'>('idle');
  const [browserDynStep, setBrowserDynStep] = useState('');
  const [browserDynProgress, setBrowserDynProgress] = useState(0);
  const [browserDynResult, setBrowserDynResult] = useState<BrowserDynamicResult | null>(null);
  const [browserDynError, setBrowserDynError] = useState<string | null>(null);
  const [browserDynJobId, setBrowserDynJobId] = useState<string | null>(null);
  const [browserDynCancelling, setBrowserDynCancelling] = useState(false);
  const [resultView, setResultView] = useState<'report' | 'context' | 'details'>('report');
  const [technicalDetails, setTechnicalDetails] = useState<UrlTechnicalDetails | null>(null);
  const [technicalDetailsLoading, setTechnicalDetailsLoading] = useState(false);
  const [technicalDetailsError, setTechnicalDetailsError] = useState<string | null>(null);
  const [showWebsitePreview, setShowWebsitePreview] = useState(false);
  const [websiteScreenshotUrl, setWebsiteScreenshotUrl] = useState<string | null>(null);
  const [websiteScreenshotLoading, setWebsiteScreenshotLoading] = useState(false);
  const [websiteScreenshotError, setWebsiteScreenshotError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const pollGenerationRef = useRef(0);
  const activePollJobRef = useRef<string | null>(null);
  const pollAbortRef = useRef<AbortController | null>(null);
  const browserPollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const browserPollGenerationRef = useRef(0);
  const activeBrowserPollJobRef = useRef<string | null>(null);
  const browserPollAbortRef = useRef<AbortController | null>(null);

  const layerIcons = [Lock, Database, Shield, Eye];
  const layerNames = ['Format Validation', 'Threat Feed Lookup', 'Domain Reputation', 'Content Analysis'];

  const layer1 = result?.details?.layers?.layer1_format || {};
  const layer2 = result?.details?.layers?.layer2_phishtank || {};
  const layer3 = result?.details?.layers?.layer3_reputation || {};
  const layer4 = result?.details?.layers?.layer4_content || {};

  const clearPoll = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    if (pollAbortRef.current) {
      pollAbortRef.current.abort();
      pollAbortRef.current = null;
    }
    activePollJobRef.current = null;
    pollGenerationRef.current += 1;
  };

  const clearBrowserPoll = () => {
    if (browserPollRef.current) {
      clearInterval(browserPollRef.current);
      browserPollRef.current = null;
    }
    if (browserPollAbortRef.current) {
      browserPollAbortRef.current.abort();
      browserPollAbortRef.current = null;
    }
    activeBrowserPollJobRef.current = null;
    browserPollGenerationRef.current += 1;
  };

  const loadTechnicalDetails = async (force = false, targetUrl?: string) => {
    const detailUrl = targetUrl || result?.details.url || url;
    if (!token || !detailUrl) return;
    if (technicalDetails && !force && !targetUrl) return;

    setTechnicalDetailsLoading(true);
    setTechnicalDetailsError(null);

    try {
      const response = await fetch(apiUrl(`/url-scan-details?url=${encodeURIComponent(detailUrl)}`), {
        headers: { Authorization: `Bearer ${token}` },
      });

      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        if (response.status === 401) {
          signOut();
          throw new Error('Session expired. Please sign in again.');
        }
        throw new Error(payload?.detail || payload?.message || 'Failed to load URL details');
      }

      setTechnicalDetails(payload as UrlTechnicalDetails);
    } catch (err) {
      setTechnicalDetailsError(err instanceof Error ? err.message : 'Failed to load URL details');
    } finally {
      setTechnicalDetailsLoading(false);
    }
  };

  const startPolling = (jobId: string, authToken: string) => {
    clearPoll();
    activePollJobRef.current = jobId;
    const pollGeneration = pollGenerationRef.current;

    const isCurrentPoll = () =>
      activePollJobRef.current === jobId && pollGenerationRef.current === pollGeneration;

    const pollOnce = async () => {
      if (!isCurrentPoll()) return;

      if (pollAbortRef.current) pollAbortRef.current.abort();
      const controller = new AbortController();
      pollAbortRef.current = controller;

      try {
        const pollRes = await fetch(apiUrl(`/analyze/url/dynamic/status/${jobId}`), {
          headers: { Authorization: `Bearer ${authToken}` },
          signal: controller.signal,
        });
        if (!isCurrentPoll()) return;

        if (!pollRes.ok) {
          if (pollRes.status === 401) {
            clearPoll();
            setDynError('Session expired. Please sign in again.');
            setDynState('error');
            setDynJobId(null);
            setDynCancelling(false);
            signOut();
            return;
          }
          if (pollRes.status === 404) {
            clearPoll();
            setDynError('URL dynamic job not found anymore. Start a new run.');
            setDynState('error');
            setDynJobId(null);
            setDynCancelling(false);
            return;
          }
          throw new Error(`Poll error ${pollRes.status}`);
        }

        const poll: DynamicPollResponse = await pollRes.json();
        if (!isCurrentPoll()) return;

        setDynStep(poll.step || '');
        setDynProgress(typeof poll.progress === 'number' ? poll.progress : 0);

        if (poll.status === 'done' && poll.result) {
          clearPoll();
          setDynState('done');
          setDynResult(poll.result);
          setDynJobId(null);
          setDynCancelling(false);
          setDynError(null);
        } else if (poll.status === 'error') {
          clearPoll();
          setDynState('error');
          setDynError(poll.error || 'Dynamic URL analysis failed.');
          setDynJobId(null);
          setDynCancelling(false);
        } else {
          setDynState('running');
        }
      } catch (e) {
        if (!isCurrentPoll()) return;
        if ((e as Error).name === 'AbortError') return;
        clearPoll();
        setDynState('error');
        setDynError(e instanceof Error ? e.message : 'Polling failed.');
        setDynJobId(null);
        setDynCancelling(false);
      }
    };

    void pollOnce();
    pollRef.current = setInterval(() => {
      void pollOnce();
    }, 1500);
  };

  const startBrowserPolling = (jobId: string, authToken: string) => {
    clearBrowserPoll();
    activeBrowserPollJobRef.current = jobId;
    const pollGeneration = browserPollGenerationRef.current;

    const isCurrentPoll = () =>
      activeBrowserPollJobRef.current === jobId && browserPollGenerationRef.current === pollGeneration;

    const pollOnce = async () => {
      if (!isCurrentPoll()) return;

      if (browserPollAbortRef.current) browserPollAbortRef.current.abort();
      const controller = new AbortController();
      browserPollAbortRef.current = controller;

      try {
        const pollRes = await fetch(apiUrl(`/analyze/url/browser-dynamic/status/${jobId}`), {
          headers: { Authorization: `Bearer ${authToken}` },
          signal: controller.signal,
        });
        if (!isCurrentPoll()) return;

        if (!pollRes.ok) {
          if (pollRes.status === 401) {
            clearBrowserPoll();
            setBrowserDynError('Session expired. Please sign in again.');
            setBrowserDynState('error');
            setBrowserDynJobId(null);
            setBrowserDynCancelling(false);
            signOut();
            return;
          }
          if (pollRes.status === 404) {
            clearBrowserPoll();
            setBrowserDynError('Fast browser dynamic job not found anymore. Start a new run.');
            setBrowserDynState('error');
            setBrowserDynJobId(null);
            setBrowserDynCancelling(false);
            return;
          }
          throw new Error(`Poll error ${pollRes.status}`);
        }

        const poll: DynamicPollResponse & { result?: BrowserDynamicResult } = await pollRes.json();
        if (!isCurrentPoll()) return;

        setBrowserDynStep(poll.step || '');
        setBrowserDynProgress(typeof poll.progress === 'number' ? poll.progress : 0);

        if (poll.status === 'done' && poll.result) {
          clearBrowserPoll();
          setBrowserDynState('done');
          setBrowserDynResult(poll.result);
          setBrowserDynJobId(null);
          setBrowserDynCancelling(false);
          setBrowserDynError(null);
        } else if (poll.status === 'error') {
          clearBrowserPoll();
          setBrowserDynState('error');
          setBrowserDynError(poll.error || 'Fast browser dynamic analysis failed.');
          setBrowserDynJobId(null);
          setBrowserDynCancelling(false);
        } else {
          setBrowserDynState('running');
        }
      } catch (e) {
        if (!isCurrentPoll()) return;
        if ((e as Error).name === 'AbortError') return;
        clearBrowserPoll();
        setBrowserDynState('error');
        setBrowserDynError(e instanceof Error ? e.message : 'Polling failed.');
        setBrowserDynJobId(null);
        setBrowserDynCancelling(false);
      }
    };

    void pollOnce();
    browserPollRef.current = setInterval(() => {
      void pollOnce();
    }, 1500);
  };

  const startDynamicUrlScan = async () => {
    if (!token || !result) {
      setDynError('Run static scan first, then start dynamic analysis.');
      return;
    }

    if (result.status === 'malicious') {
      setDynError('Dynamic URL analysis blocked by policy: static verdict is malicious.');
      return;
    }

    setDynState('running');
    setDynError(null);
    setDynResult(null);
    setDynStep('Preparing URL sandbox environment...');
    setDynProgress(5);
    setDynCancelling(false);

    try {
      const formData = new URLSearchParams({ url: result.details.url || url });
      const res = await fetch(apiUrl('/analyze/url/dynamic'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Bearer ${token}`,
        },
        body: formData,
      });

      const payload = await res.json().catch(() => ({}));
      if (!res.ok) {
        if (res.status === 401) {
          signOut();
          throw new Error('Session expired. Please sign in again.');
        }
        if (res.status === 409) {
          throw new Error('Another dynamic analysis is already running. Cancel or wait for completion.');
        }
        if (res.status === 422) {
          const detail = payload?.detail;
          if (typeof detail === 'string') {
            throw new Error(detail);
          }
          if (detail?.message) {
            throw new Error(detail.message);
          }
        }
        throw new Error(payload?.detail || payload?.message || `Dynamic scan failed (${res.status})`);
      }

      const jobId = String(payload.job_id || '');
      if (!jobId) {
        throw new Error('Backend did not return a dynamic job id.');
      }
      setDynJobId(jobId);
      startPolling(jobId, token);
    } catch (e) {
      clearPoll();
      setDynState('error');
      setDynError(e instanceof Error ? e.message : 'Failed to start dynamic URL analysis.');
      setDynJobId(null);
      setDynCancelling(false);
    }
  };

  const startBrowserDynamicUrlScan = async () => {
    if (!token || !result) {
      setBrowserDynError('Run static scan first, then start browser dynamic analysis.');
      return;
    }

    if (result.status === 'malicious') {
      setBrowserDynError('Fast browser dynamic analysis blocked by policy: static verdict is malicious.');
      return;
    }

    setBrowserDynState('running');
    setBrowserDynError(null);
    setBrowserDynResult(null);
    setBrowserDynStep('Launching browser instrumentation...');
    setBrowserDynProgress(5);
    setBrowserDynCancelling(false);

    try {
      const formData = new URLSearchParams({ url: result.details.url || url });
      const res = await fetch(apiUrl('/analyze/url/browser-dynamic'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Bearer ${token}`,
        },
        body: formData,
      });

      const payload = await res.json().catch(() => ({}));
      if (!res.ok) {
        if (res.status === 401) {
          signOut();
          throw new Error('Session expired. Please sign in again.');
        }
        if (res.status === 409) {
          throw new Error('Another fast browser dynamic analysis is already running. Cancel or wait for completion.');
        }
        if (res.status === 422) {
          const detail = payload?.detail;
          if (typeof detail === 'string') {
            throw new Error(detail);
          }
          if (detail?.message) {
            throw new Error(detail.message);
          }
        }
        throw new Error(payload?.detail || payload?.message || `Fast browser dynamic scan failed (${res.status})`);
      }

      const jobId = String(payload.job_id || '');
      if (!jobId) {
        throw new Error('Backend did not return a fast browser dynamic job id.');
      }
      setBrowserDynJobId(jobId);
      startBrowserPolling(jobId, token);
    } catch (e) {
      clearBrowserPoll();
      setBrowserDynState('error');
      setBrowserDynError(e instanceof Error ? e.message : 'Failed to start fast browser dynamic analysis.');
      setBrowserDynJobId(null);
      setBrowserDynCancelling(false);
    }
  };

  const cancelDynamic = async () => {
    if (!token || !dynJobId) return;
    setDynCancelling(true);
    try {
      await fetch(apiUrl(`/analyze/url/dynamic/cancel/${dynJobId}`), {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
    } catch {
      // Best effort cancellation.
    } finally {
      clearPoll();
      setDynState('idle');
      setDynStep('');
      setDynProgress(0);
      setDynJobId(null);
      setDynCancelling(false);
    }
  };

  const refreshHookFact = (nextResult?: ScanResult | null, statsOverride?: ThreatFeedStats | null) => {
    const stats = statsOverride ?? feedStats;
    const facts: string[] = [
      'Security fact: URL format anomalies are often the fastest phishing clue.',
      'Security fact: Reputation and content signals together reduce false positives.',
      'Security fact: Layered analysis catches threats single checks miss.',
    ];

    if (stats) {
      facts.push(`Threat feed currently tracks ${stats.total_threat_urls.toLocaleString()} malicious URLs.`);
      facts.push(`${stats.unique_domains.toLocaleString()} unique malicious domains are indexed in your feed.`);
      facts.push(`${stats.scan_totals.total.toLocaleString()} URL/file scans are logged in your platform.`);
      facts.push(`${stats.scan_totals.malicious.toLocaleString()} historical scans were marked malicious.`);
      facts.push(`${stats.scan_totals.suspicious.toLocaleString()} historical scans were marked suspicious.`);
    }

    if (nextResult) {
      facts.push(`Latest URL risk score: ${nextResult.details.overall_threat_score}/100.`);
      if (nextResult.details.layers.layer2_phishtank?.found) {
        facts.push('This URL matched a known threat feed indicator.');
      }
      if ((nextResult.details.layers.layer4_content?.indicators?.length ?? 0) > 0) {
        facts.push(`Content analysis found ${(nextResult.details.layers.layer4_content.indicators ?? []).length} suspicious indicators.`);
      }
    }

    setHookFact(pickRandom(facts));
  };

  useEffect(() => {
    if (!token) return;

    const loadStats = async () => {
      try {
        const res = await fetch(apiUrl('/threat-feed/stats'), {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) return;
        const data: ThreatFeedStats = await res.json();
        setFeedStats(data);
        refreshHookFact(undefined, data);
      } catch {
        // Best effort only.
      }
    };

    void loadStats();
  }, [token]);

  useEffect(() => () => {
    clearPoll();
    clearBrowserPoll();
  }, []);

  useEffect(() => {
    return () => {
      if (websiteScreenshotUrl) {
        URL.revokeObjectURL(websiteScreenshotUrl);
      }
    };
  }, [websiteScreenshotUrl]);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    const normalizedUrl = normalizeUrlInput(url);

    if (!normalizedUrl || !user || !token) {
      setError('Please login and enter a valid URL');
      return;
    }

    setScanning(true);
    setResult(null);
    setError(null);
    setCurrentLayer(0);
    clearPoll();
    clearBrowserPoll();
    setDynState('idle');
    setDynStep('');
    setDynProgress(0);
    setDynResult(null);
    setDynError(null);
    setDynJobId(null);
    setDynCancelling(false);
    setBrowserDynState('idle');
    setBrowserDynStep('');
    setBrowserDynProgress(0);
    setBrowserDynResult(null);
    setBrowserDynError(null);
    setBrowserDynJobId(null);
    setBrowserDynCancelling(false);
    setResultView('report');
    setTechnicalDetails(null);
    setTechnicalDetailsError(null);
    setTechnicalDetailsLoading(false);
    setShowWebsitePreview(false);
    setWebsiteScreenshotError(null);
    setWebsiteScreenshotLoading(false);
    if (websiteScreenshotUrl) {
      URL.revokeObjectURL(websiteScreenshotUrl);
    }
    setWebsiteScreenshotUrl(null);

    try {
      const parsedUrl = new URL(normalizedUrl);
      const finalUrl = parsedUrl.toString();
      setUrl(finalUrl);

      for (let i = 1; i <= 4; i++) {
        setCurrentLayer(i);
        await new Promise((resolve) => setTimeout(resolve, 600));
      }

      const formData = new URLSearchParams({ url: finalUrl });

      const res = await fetch(apiUrl('/url-scan-advanced'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Bearer ${token}`,
        },
        body: formData,
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.detail || data.message || 'Scan failed');
      }

      const details = data.details || {};
      details.layers = {
        layer1_format: details.layers?.layer1_format || {},
        layer2_phishtank: details.layers?.layer2_phishtank || {},
        layer3_reputation: details.layers?.layer3_reputation || {},
        layer4_content: details.layers?.layer4_content || {},
      };

      const nextResult: ScanResult = {
        status: data.status || 'clean',
        threat_score: data.threat_score || 0,
        details,
      };

      setPreviousResult(result);
      setResult(nextResult);
      refreshHookFact(nextResult);
      void loadTechnicalDetails(false, finalUrl);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setScanning(false);
      setCurrentLayer(0);
    }
  };

  const loadWebsiteScreenshot = async (force = false) => {
    const targetUrl = technicalDetails?.http_response?.final_url || result?.details.url || url;
    if (!token || !targetUrl) return;
    if (websiteScreenshotUrl && !force) return;

    setWebsiteScreenshotLoading(true);
    setWebsiteScreenshotError(null);
    setWebsiteScreenshotUrl((current) => {
      if (current) URL.revokeObjectURL(current);
      return force ? null : current;
    });

    try {
      const response = await fetch(apiUrl(`/url-scan-screenshot?url=${encodeURIComponent(targetUrl)}`), {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        if (response.status === 401) {
          signOut();
          throw new Error('Session expired. Please sign in again.');
        }
        throw new Error(payload?.detail || payload?.message || 'Failed to capture website screenshot');
      }

      const blob = await response.blob();
      const objectUrl = URL.createObjectURL(blob);
      setWebsiteScreenshotUrl((current) => {
        if (current) URL.revokeObjectURL(current);
        return objectUrl;
      });
    } catch (err) {
      setWebsiteScreenshotUrl((current) => {
        if (current) URL.revokeObjectURL(current);
        return null;
      });
      setWebsiteScreenshotError(err instanceof Error ? err.message : 'Failed to capture website screenshot');
    } finally {
      setWebsiteScreenshotLoading(false);
    }
  };

  const cancelBrowserDynamic = async () => {
    if (!token || !browserDynJobId) return;
    setBrowserDynCancelling(true);
    try {
      await fetch(apiUrl(`/analyze/url/browser-dynamic/cancel/${browserDynJobId}`), {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
    } catch {
      // Best effort cancellation.
    } finally {
      clearBrowserPoll();
      setBrowserDynState('idle');
      setBrowserDynStep('');
      setBrowserDynProgress(0);
      setBrowserDynJobId(null);
      setBrowserDynCancelling(false);
    }
  };

  const getStatusIcon = () => {
    if (!result) return null;
    switch (result.status) {
      case 'clean':
        return <CheckCircle className="w-16 h-16 text-green-400" />;
      case 'malicious':
        return <AlertCircle className="w-16 h-16 text-red-400" />;
      case 'suspicious':
        return <AlertTriangle className="w-16 h-16 text-yellow-400" />;
      default:
        return <AlertTriangle className="w-16 h-16 text-slate-400" />;
    }
  };

  const getStatusColor = (status?: string) => {
    switch (status) {
      case 'clean':
        return 'text-green-400 bg-green-500/10 border-green-500/30';
      case 'malicious':
        return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'suspicious':
        return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      default:
        return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
    }
  };

  const getThreatLevelColor = (level?: string) => {
    switch (level) {
      case 'high':
        return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'medium':
        return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'low':
        return 'text-green-400 bg-green-500/10 border-green-500/30';
      default:
        return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
    }
  };

  const scoreBreakdown = useMemo(() => {
    if (!result) return null;

    const l1 = layer1.passed === false ? 20 : 0;
    const l2 = layer2.found ? (layer2.verified ? 60 : 40) : 0;
    const reputationLoss = 100 - (layer3.reputation_score ?? 100);
    const l3 = Math.max(0, Math.round(reputationLoss * 0.25));
    const l4 = layer4.threat_score ?? 0;

    return [
      { label: 'Layer 1', detail: 'Format', score: l1 },
      { label: 'Layer 2', detail: 'Threat Feed', score: l2 },
      { label: 'Layer 3', detail: 'Reputation', score: l3 },
      { label: 'Layer 4', detail: 'Content', score: l4 },
    ];
  }, [result, layer1.passed, layer2.found, layer2.verified, layer3.reputation_score, layer4.threat_score]);

  const previousDelta = useMemo(() => {
    if (!result || !previousResult) return null;
    return result.details.overall_threat_score - previousResult.details.overall_threat_score;
  }, [result, previousResult]);

  return (
    <div className="flex h-full min-h-0 flex-1 flex-col overflow-hidden bg-slate-900">
      <style>{`
        .global-scroll::-webkit-scrollbar { width: 14px; }
        .global-scroll::-webkit-scrollbar-track { background: #1e293b; }
        .global-scroll::-webkit-scrollbar-thumb { background: #475569; border-radius: 7px; border: 3px solid #1e293b; }
        .global-scroll::-webkit-scrollbar-thumb:hover { background: #64748b; }
        .global-scroll { scrollbar-width: thin; scrollbar-color: #475569 #1e293b; }
      `}</style>

      <div className="flex-shrink-0 p-4 pb-4 sm:p-6 sm:pb-4 xl:p-8 xl:pb-4">
        <div className="flex items-center justify-between gap-4 mb-4">
          <div>
            <h2 className="text-3xl font-bold text-white mb-2">{translateText('Advanced URL Scanner')}</h2>
            <p className="text-slate-400">{translateText('4-layer security analysis for comprehensive threat detection')}</p>
          </div>
        </div>
      </div>

      <div className="global-scroll min-h-0 flex-1 overflow-y-auto px-4 pb-8 sm:px-6 xl:px-8">
        <div className="mx-auto max-w-5xl space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2 bg-slate-800/50 border border-slate-700 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-3 text-cyan-300">
                <Shield className="w-4 h-4" />
                <p className="text-sm font-semibold">{translateText('URL Analysis Layers')}</p>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
                  <p className="text-slate-400">{translateText('Layer 1')}</p>
                  <p className="text-white font-semibold">{translateText('Format Validation')}</p>
                  <p className="text-slate-500 text-xs mt-1">{translateText('Protocol, syntax, suspicious patterns')}</p>
                </div>
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
                  <p className="text-slate-400">{translateText('Layer 2')}</p>
                  <p className="text-white font-semibold">{translateText('Threat Feed Lookup')}</p>
                  <p className="text-slate-500 text-xs mt-1">{translateText('Known malicious URL/domain match')}</p>
                </div>
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
                  <p className="text-slate-400">{translateText('Layer 3')}</p>
                  <p className="text-white font-semibold">{translateText('Domain Reputation')}</p>
                  <p className="text-slate-500 text-xs mt-1">{translateText('Trust score and domain risk checks')}</p>
                </div>
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
                  <p className="text-slate-400">{translateText('Layer 4')}</p>
                  <p className="text-white font-semibold">{translateText('Content Analysis')}</p>
                  <p className="text-slate-500 text-xs mt-1">{translateText('Indicators and behavior scoring')}</p>
                </div>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mt-3 text-sm">
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
                  <p className="text-slate-400">{translateText('Malicious URLs')}</p>
                  <p className="text-white font-bold text-lg">{feedStats ? feedStats.total_threat_urls.toLocaleString() : '...'}</p>
                </div>
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
                  <p className="text-slate-400">{translateText('Verified URLs')}</p>
                  <p className="text-emerald-400 font-bold text-lg">{feedStats ? feedStats.verified_threat_urls.toLocaleString() : '...'}</p>
                </div>
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
                  <p className="text-slate-400">{translateText('Malicious Domains')}</p>
                  <p className="text-cyan-300 font-bold text-lg">{feedStats ? feedStats.unique_domains.toLocaleString() : '...'}</p>
                </div>
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
                  <p className="text-slate-400">{translateText('Platform Scans')}</p>
                  <p className="text-white font-bold text-lg">{feedStats ? feedStats.scan_totals.total.toLocaleString() : '...'}</p>
                </div>
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
                  <p className="text-slate-400">{translateText('Malicious Verdicts')}</p>
                  <p className="text-red-400 font-bold text-lg">{feedStats ? feedStats.scan_totals.malicious.toLocaleString() : '...'}</p>
                </div>
              </div>
            </div>
            <div className="bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border border-cyan-500/30 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2 text-cyan-300">
                <Sparkles className="w-4 h-4" />
                <p className="text-sm font-semibold">{translateText('Did You Know?')}</p>
              </div>
              <p className="text-slate-200 text-sm leading-relaxed">{translateText(hookFact)}</p>
            </div>
          </div>

          <form onSubmit={handleScan} className="mb-6 flex flex-col gap-4 lg:flex-row">
            <div className="flex-1 relative">
              <Globe className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="example.com or https://example.com"
                className="w-full pl-12 pr-4 py-4 bg-slate-900/50 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 transition"
                required
                disabled={scanning}
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
              />
            </div>
            <button
              type="submit"
              disabled={scanning || !url}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 px-8 py-4 font-semibold text-white transition hover:from-cyan-600 hover:to-blue-700 disabled:cursor-not-allowed disabled:opacity-50 lg:w-auto"
            >
              <Search className="w-5 h-5" />
              {translateText('Search URL')}
            </button>
          </form>

          {scanning && (
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 mb-6">
              <div className="mb-4 grid grid-cols-2 gap-4 xl:grid-cols-4">
                {layerNames.map((name, idx) => {
                  const Icon = layerIcons[idx];
                  const active = currentLayer === idx + 1;
                  const done = currentLayer > idx + 1;
                  return (
                    <div
                      key={name}
                      className={`text-center p-4 rounded-lg border transition ${
                        active
                          ? 'bg-cyan-500/20 border-cyan-500/50'
                          : done
                          ? 'bg-cyan-500/10 border-cyan-500/20'
                          : 'bg-slate-900/50 border-slate-600'
                      }`}
                    >
                      <Icon className={`w-6 h-6 mx-auto mb-2 ${active || done ? 'text-cyan-400' : 'text-slate-500'}`} />
                      <p className={`text-sm font-medium ${active || done ? 'text-white' : 'text-slate-500'}`}>{translateText('Layer')} {idx + 1}</p>
                      <p className={`text-xs ${active || done ? 'text-slate-300' : 'text-slate-600'}`}>{translateText(name)}</p>
                    </div>
                  );
                })}
              </div>
              <div className="text-center">
                <Loader2 className="w-8 h-8 text-cyan-400 animate-spin mx-auto mb-2" />
                <p className="text-slate-300">{translateText('Analyzing...')} {translateText('Layer')} {currentLayer}/4</p>
              </div>
            </div>
          )}

          {error && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 mb-6">
              <div className="flex items-center gap-2 text-red-400">
                <AlertCircle className="w-5 h-5" />
                <p className="font-medium">{error}</p>
              </div>
            </div>
          )}

          {dynError && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 mb-6">
              <div className="flex items-center gap-2 text-red-400">
                <AlertCircle className="w-5 h-5" />
                <p className="font-medium">{dynError}</p>
              </div>
            </div>
          )}

          {result && !scanning && (
            <div className="space-y-6">
              <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-8 text-center">
                <div className="flex justify-center mb-4">{getStatusIcon()}</div>
                <h3 className="text-2xl font-bold text-white mb-2">{translateText('Scan Complete')}</h3>
                <span className={`inline-block px-4 py-2 rounded-full text-sm font-semibold border ${getStatusColor(result.status)}`}>
                  {translateText(result.status.charAt(0).toUpperCase() + result.status.slice(1))}
                </span>
                <div className="mt-4">
                  <p className="text-slate-400 text-sm mb-2">{translateText('Overall Threat Score')}</p>
                  <div className="flex items-center justify-center gap-3">
                    <div className="flex-1 max-w-md bg-slate-900/50 rounded-full h-3">
                      <div
                        className={`h-full rounded-full transition-all ${
                          result.details.overall_threat_score >= 70
                            ? 'bg-red-500'
                            : result.details.overall_threat_score >= 40
                            ? 'bg-yellow-500'
                            : 'bg-green-500'
                        }`}
                        style={{ width: `${result.details.overall_threat_score}%` }}
                      />
                    </div>
                    <span className="text-white font-bold text-xl min-w-[3rem]">{result.details.overall_threat_score}/100</span>
                  </div>
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-700 bg-slate-800/40 p-4">
                <div>
                  <p className="text-white font-semibold">{translateText('Result Views')}</p>
                  <p className="text-sm text-slate-400">{translateText('Switch between the scan report, threat context, and technical details.')}</p>
                </div>
                <div className="inline-flex rounded-xl border border-slate-700 bg-slate-900/60 p-1">
                  <button
                    type="button"
                    onClick={() => setResultView('report')}
                    className={`rounded-lg px-4 py-2 text-sm font-medium transition ${
                      resultView === 'report'
                        ? 'bg-cyan-500 text-white shadow'
                        : 'text-slate-300 hover:bg-slate-700/70 hover:text-white'
                    }`}
                  >
                    {translateText('Scan Report')}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setResultView('context');
                      void loadTechnicalDetails();
                    }}
                    className={`rounded-lg px-4 py-2 text-sm font-medium transition ${
                      resultView === 'context'
                        ? 'bg-cyan-500 text-white shadow'
                        : 'text-slate-300 hover:bg-slate-700/70 hover:text-white'
                    }`}
                  >
                    {translateText('Threat Context')}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setResultView('details');
                      void loadTechnicalDetails();
                    }}
                    className={`rounded-lg px-4 py-2 text-sm font-medium transition ${
                      resultView === 'details'
                        ? 'bg-cyan-500 text-white shadow'
                        : 'text-slate-300 hover:bg-slate-700/70 hover:text-white'
                    }`}
                  >
                    {translateText('Technical Details')}
                  </button>
                </div>
              </div>

              {resultView === 'report' ? (
              <>
              <div className="rounded-xl border border-slate-700 bg-gradient-to-r from-slate-800/90 to-slate-900/90 p-6">
                <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-[0.28em] text-cyan-300">{translateText('Scan Report')}</p>
                    <h4 className="mt-2 text-2xl font-bold text-white">{result.details.url}</h4>
                    <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
                      {translateText('This section focuses on the final verdict, scoring logic, layer-by-layer reasoning, and optional dynamic validation.')}
                    </p>
                  </div>
                  <div className={`rounded-xl border px-4 py-3 text-sm font-semibold ${getStatusColor(result.status)}`}>
                    {translateText(result.status.charAt(0).toUpperCase() + result.status.slice(1))} · {result.details.overall_threat_score}/100
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                  <div className="flex items-center gap-2 mb-4">
                    <BarChart3 className="w-4 h-4 text-cyan-400" />
                    <h4 className="text-white font-semibold">{translateText('Verdict Breakdown')}</h4>
                  </div>
                  <div className="space-y-3">
                    {scoreBreakdown?.map((item) => (
                      <div key={item.label} className="flex items-center justify-between rounded-lg bg-slate-900/50 border border-slate-700 p-3">
                        <div>
                          <p className="text-white text-sm font-medium">{translateText(item.label)}</p>
                          <p className="text-slate-500 text-xs">{translateText(item.detail)}</p>
                        </div>
                        <p className="text-cyan-300 font-semibold">+{item.score}</p>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                  <div className="flex items-center gap-2 mb-4">
                    <TrendingUp className="w-4 h-4 text-cyan-400" />
                    <h4 className="text-white font-semibold">{translateText('Scan Comparison')}</h4>
                  </div>
                  {previousResult ? (
                    <div className="space-y-3">
                      <div className="rounded-lg bg-slate-900/50 border border-slate-700 p-3">
                        <p className="text-slate-400 text-sm">{translateText('Previous score')}</p>
                        <p className="text-white font-semibold">{previousResult.details.overall_threat_score}/100</p>
                      </div>
                      <div className="rounded-lg bg-slate-900/50 border border-slate-700 p-3">
                        <p className="text-slate-400 text-sm">{translateText('Delta')}</p>
                        <p className={`font-semibold ${
                          (previousDelta ?? 0) > 0 ? 'text-red-400' : (previousDelta ?? 0) < 0 ? 'text-green-400' : 'text-slate-300'
                        }`}>
                          {previousDelta === null ? '0' : `${previousDelta > 0 ? '+' : ''}${previousDelta}`}
                        </p>
                      </div>
                    </div>
                  ) : (
                    <div className="rounded-lg bg-slate-900/50 border border-slate-700 p-3">
                      <p className="text-slate-400 text-sm">{translateText('Run one more scan to unlock comparison insights.')}</p>
                    </div>
                  )}
                </div>
              </div>

              <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                <div className="flex items-center justify-between gap-4 mb-4">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-purple-500/10 border border-purple-500/30 rounded-lg flex items-center justify-center text-purple-400">
                      <Monitor className="w-5 h-5" />
                    </div>
                    <div>
                      <h4 className="text-white font-semibold">{translateText('Dynamic URL Analysis (Sandbox)')}</h4>
                      <p className="text-slate-400 text-sm">{translateText('Windows Sandbox execution for process, network, and deeper host-level behaviour. Runs only for static clean/suspicious URLs.')}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {dynState === 'running' ? (
                      <button
                        onClick={cancelDynamic}
                        disabled={dynCancelling}
                        className="px-4 py-2 rounded-lg border border-red-500/40 text-red-300 hover:bg-red-500/10 disabled:opacity-60 transition flex items-center gap-2"
                      >
                        <XCircle className="w-4 h-4" />
                        {dynCancelling ? translateText('Cancelling...') : translateText('Cancel')}
                      </button>
                    ) : (
                      <button
                        onClick={startDynamicUrlScan}
                        disabled={result.status === 'malicious'}
                        className="px-4 py-2 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 text-white font-semibold hover:from-purple-700 hover:to-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition flex items-center gap-2"
                      >
                        <Play className="w-4 h-4" />
                        {translateText('Run Dynamic URL Scan')}
                      </button>
                    )}
                  </div>
                </div>

                {result.status === 'malicious' && (
                  <div className="mb-4 bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-red-300 text-sm">
                    {translateText('Policy block active: this URL is statically malicious, so sandbox launch is refused.')}
                  </div>
                )}

                {dynState === 'running' && (
                  <div className="rounded-lg border border-purple-500/30 bg-slate-900/50 p-4 space-y-3">
                    <div className="flex items-center justify-between text-sm">
                      <p className="text-slate-300">{dynStep || translateText('Running sandbox URL analysis...')}</p>
                      <p className="text-purple-300 font-semibold">{dynProgress}%</p>
                    </div>
                    <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-purple-600 to-indigo-600 transition-all duration-500"
                        style={{ width: `${Math.max(0, Math.min(100, dynProgress))}%` }}
                      />
                    </div>
                    {dynJobId && <p className="text-xs text-slate-500">Job ID: {dynJobId}</p>}
                  </div>
                )}

                {dynResult && dynState === 'done' && (
                  <div className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                      <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-3">
                        <p className="text-slate-400 text-xs">{translateText('Verdict')}</p>
                        <p className={`font-semibold ${
                          dynResult.verdict === 'malicious' ? 'text-red-400' : dynResult.verdict === 'suspicious' ? 'text-yellow-400' : 'text-green-400'
                        }`}>{translateText(dynResult.verdict.charAt(0).toUpperCase() + dynResult.verdict.slice(1))}</p>
                      </div>
                      <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-3">
                        <p className="text-slate-400 text-xs">{translateText('Dynamic Threat Score')}</p>
                        <p className="text-white font-semibold">{dynResult.threatScore}/100</p>
                      </div>
                      <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-3">
                        <p className="text-slate-400 text-xs">{translateText('Duration')}</p>
                        <p className="text-white font-semibold">{dynResult.duration}s</p>
                      </div>
                      <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-3">
                        <p className="text-slate-400 text-xs">{translateText('Observed Connections')}</p>
                        <p className="text-white font-semibold">{dynResult.network.length}</p>
                      </div>
                    </div>

                    {dynResult.summary.length > 0 && (
                      <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                        <p className="text-white font-medium mb-2">{translateText('Dynamic Summary')}</p>
                        <ul className="space-y-1">
                          {dynResult.summary.slice(0, 8).map((item, idx) => (
                            <li key={idx} className="text-sm text-slate-300">- {item}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                      <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                        <p className="text-white font-medium mb-2">{translateText('Top Processes')}</p>
                        {dynResult.processes.length === 0 ? (
                          <p className="text-sm text-slate-400">{translateText('No notable process activity.')}</p>
                        ) : (
                          <div className="space-y-1">
                            {dynResult.processes.slice(0, 6).map((p, idx) => (
                              <div key={`${p.name}-${p.pid ?? idx}`} className="text-sm text-slate-300 flex items-center justify-between">
                                <span>{p.name}{p.pid ? ` (PID ${p.pid})` : ''}</span>
                                {p.suspicious ? <span className="text-red-400">{translateText('Suspicious')}</span> : <span className="text-slate-500">{translateText('Normal')}</span>}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                      <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                        <p className="text-white font-medium mb-2">{translateText('Top Network Connections')}</p>
                        {dynResult.network.length === 0 ? (
                          <p className="text-sm text-slate-400">{translateText('No external network telemetry captured.')}</p>
                        ) : (
                          <div className="space-y-1">
                            {dynResult.network.slice(0, 6).map((n, idx) => (
                              <div key={`${n.destination ?? 'dest'}-${n.port ?? idx}`} className="text-sm text-slate-300 flex items-center justify-between">
                                <span>{n.protocol ?? 'TCP'}{' -> '}{n.destination ?? 'unknown'}:{n.port ?? 0}</span>
                                {n.suspicious ? <span className="text-red-400">{translateText('Suspicious')}</span> : <span className="text-slate-500">{translateText(n.classification ?? 'normal')}</span>}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>

              <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 bg-cyan-500/10 border border-cyan-500/30 rounded-lg flex items-center justify-center text-cyan-400">
                    <Lock className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="text-white font-semibold">{translateText('Layer 1')}: {translateText('Format Validation')}</h4>
                    <p className="text-slate-400 text-sm">{translateText('URL structure and syntax analysis')}</p>
                  </div>
                </div>
                {layer1.issues && layer1.issues.length > 0 ? (
                  <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                    <p className="text-yellow-400 font-medium mb-2">{translateText('Issues Detected:')}</p>
                    <ul className="space-y-1">
                      {layer1.issues.map((issue: string, idx: number) => (
                        <li key={idx} className="text-white text-sm">- {issue}</li>
                      ))}
                    </ul>
                  </div>
                ) : (
                  <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                    <p className="text-green-400">{translateText('No format issues detected')}</p>
                  </div>
                )}
              </div>

              <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 bg-cyan-500/10 border border-cyan-500/30 rounded-lg flex items-center justify-center text-cyan-400">
                    <Database className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="text-white font-semibold">{translateText('Layer 2')}: {translateText('Threat Feed Database')}</h4>
                    <p className="text-slate-400 text-sm">{translateText('Known malicious URL and domain lookup')}</p>
                  </div>
                </div>
                {Object.keys(layer2).length > 0 ? (
                  <div className={`rounded-lg p-4 border ${getThreatLevelColor(layer2.threat_level || 'low')}`}>
                    <p className="font-medium mb-2">{translateText(layer2.found ? 'Found in Database' : 'Not Found in Database')}</p>
                    <p className="text-sm opacity-90">{layer2.message || translateText('No additional info')}</p>
                    {layer2.source && <p className="text-sm mt-2 opacity-80">{translateText('Source')}: {layer2.source}</p>}
                    {layer2.domain_matches !== undefined && (
                      <p className="text-sm mt-1 opacity-80">{translateText('Domain matches:')} {layer2.domain_matches}</p>
                    )}
                  </div>
                ) : (
                  <div className="bg-slate-700/20 border border-slate-600 rounded-lg p-4">
                    <p className="text-slate-300 text-sm">{translateText('No Layer 2 data returned.')}</p>
                  </div>
                )}
              </div>

              <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 bg-cyan-500/10 border border-cyan-500/30 rounded-lg flex items-center justify-center text-cyan-400">
                    <Shield className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="text-white font-semibold">{translateText('Layer 3')}: {translateText('Domain Reputation')}</h4>
                    <p className="text-slate-400 text-sm">{translateText('Domain trust and reputation analysis')}</p>
                  </div>
                </div>
                {Object.keys(layer3).length > 0 ? (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-300">{translateText('Reputation Score')}</span>
                      <span className="text-white font-bold">{layer3.reputation_score ?? 0}/100</span>
                    </div>
                    {layer3.issues && layer3.issues.length > 0 ? (
                      <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3">
                        <p className="text-yellow-400 font-medium text-sm mb-2">{translateText('Reputation Issues:')}</p>
                        <ul className="space-y-1">
                          {layer3.issues.map((issue: string, idx: number) => (
                            <li key={idx} className="text-white text-sm">- {issue}</li>
                          ))}
                        </ul>
                      </div>
                    ) : (
                      <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3">
                        <p className="text-green-400 text-sm">{translateText('No reputation issues detected')}</p>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="bg-slate-700/20 border border-slate-600 rounded-lg p-4">
                    <p className="text-slate-300 text-sm">{translateText('No Layer 3 data returned.')}</p>
                  </div>
                )}
              </div>

              <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 bg-cyan-500/10 border border-cyan-500/30 rounded-lg flex items-center justify-center text-cyan-400">
                    <Eye className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="text-white font-semibold">{translateText('Layer 4')}: {translateText('Content Analysis')}</h4>
                    <p className="text-slate-400 text-sm">{translateText('Behavioral and content indicators')}</p>
                  </div>
                </div>
                {Object.keys(layer4).length > 0 ? (
                  <>
                    {layer4.indicators && layer4.indicators.length > 0 ? (
                      <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                        <p className="text-yellow-400 font-medium mb-2">{translateText('Indicators Found:')}</p>
                        <ul className="space-y-1">
                          {layer4.indicators.map((indicator: string, idx: number) => (
                            <li key={idx} className="text-white text-sm">- {indicator}</li>
                          ))}
                        </ul>
                      </div>
                    ) : (
                      <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                        <p className="text-green-400">{translateText('No suspicious content indicators')}</p>
                      </div>
                    )}
                    <div className="mt-3 text-sm text-slate-300 flex items-center justify-between">
                      <span>{translateText('Content threat score')}</span>
                      <span className="text-white font-semibold">{layer4.threat_score ?? 0}</span>
                    </div>
                  </>
                ) : (
                  <div className="bg-slate-700/20 border border-slate-600 rounded-lg p-4">
                    <p className="text-slate-300 text-sm">{translateText('No Layer 4 data returned.')}</p>
                  </div>
                )}
              </div>
              </>
              ) : resultView === 'context' ? (
                <div className="space-y-6">
                  <div className="flex items-center justify-between gap-4 rounded-xl border border-slate-700 bg-slate-800/50 p-5">
                    <div>
                      <h4 className="text-lg font-semibold text-white">{translateText('Threat Context')}</h4>
                      <p className="text-sm text-slate-400">{translateText('History, domain ownership, request summary, and page preview for the scanned website.')}</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => void loadTechnicalDetails(true)}
                      disabled={technicalDetailsLoading}
                      className="inline-flex items-center gap-2 rounded-lg border border-slate-600 bg-slate-900/50 px-3 py-2 text-sm text-slate-200 transition hover:border-cyan-500/40 hover:text-cyan-200 disabled:opacity-60"
                    >
                      <RefreshCw className={`h-4 w-4 ${technicalDetailsLoading ? 'animate-spin' : ''}`} />
                      {translateText('Refresh Context')}
                    </button>
                  </div>

                  {technicalDetailsError ? (
                    <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
                      {technicalDetailsError}
                    </div>
                  ) : technicalDetailsLoading && !technicalDetails ? (
                    <div className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-800/50 p-5 text-slate-300">
                      <Loader2 className="h-4 w-4 animate-spin text-cyan-400" />
                      <span>{translateText('Loading technical details...')}</span>
                    </div>
                  ) : technicalDetails ? (
                    <>
                      <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-5">
                        <div className="mb-4 flex items-center justify-between gap-4">
                          <div className="flex items-center gap-3">
                            <div className="w-10 h-10 bg-cyan-500/10 border border-cyan-500/30 rounded-lg flex items-center justify-center text-cyan-400">
                              <Globe className="w-5 h-5" />
                            </div>
                            <div>
                              <h4 className="font-semibold text-white">{translateText('Fast Browser Dynamic')}</h4>
                              <p className="text-sm text-slate-400">{translateText('Headless browser instrumentation for requests, redirects, console, dialogs, downloads, DOM forms, and screenshots.')}</p>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            {browserDynState === 'running' ? (
                              <button
                                onClick={cancelBrowserDynamic}
                                disabled={browserDynCancelling}
                                className="px-4 py-2 rounded-lg border border-red-500/40 text-red-300 hover:bg-red-500/10 disabled:opacity-60 transition flex items-center gap-2"
                              >
                                <XCircle className="w-4 h-4" />
                                {browserDynCancelling ? translateText('Cancelling...') : translateText('Cancel')}
                              </button>
                            ) : (
                              <button
                                onClick={startBrowserDynamicUrlScan}
                                disabled={result.status === 'malicious'}
                                className="px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-sky-600 text-white font-semibold hover:from-cyan-700 hover:to-sky-700 disabled:opacity-50 disabled:cursor-not-allowed transition flex items-center gap-2"
                              >
                                <Play className="w-4 h-4" />
                                {translateText('Run Fast Browser Scan')}
                              </button>
                            )}
                          </div>
                        </div>

                        {browserDynState === 'running' && (
                          <div className="rounded-lg border border-cyan-500/30 bg-slate-900/50 p-4 space-y-3">
                            <div className="flex items-center justify-between text-sm">
                              <p className="text-slate-300">{browserDynStep || translateText('Running browser dynamic analysis...')}</p>
                              <p className="text-cyan-300 font-semibold">{browserDynProgress}%</p>
                            </div>
                            <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                              <div
                                className="h-full bg-gradient-to-r from-cyan-600 to-sky-600 transition-all duration-500"
                                style={{ width: `${Math.max(0, Math.min(100, browserDynProgress))}%` }}
                              />
                            </div>
                            {browserDynJobId && <p className="text-xs text-slate-500">Job ID: {browserDynJobId}</p>}
                          </div>
                        )}

                        {browserDynError && browserDynState === 'error' && (
                          <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
                            {browserDynError}
                          </div>
                        )}

                        {browserDynResult && browserDynState === 'done' && (
                          <div className="space-y-4">
                            <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
                              <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-3">
                                <p className="text-slate-400 text-xs">{translateText('Verdict')}</p>
                                <p className={`font-semibold ${
                                  browserDynResult.verdict === 'malicious' ? 'text-red-400' : browserDynResult.verdict === 'suspicious' ? 'text-yellow-400' : 'text-green-400'
                                }`}>{translateText(browserDynResult.verdict.charAt(0).toUpperCase() + browserDynResult.verdict.slice(1))}</p>
                              </div>
                              <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-3">
                                <p className="text-slate-400 text-xs">{translateText('Dynamic Threat Score')}</p>
                                <p className="text-white font-semibold">{browserDynResult.threatScore}/100</p>
                              </div>
                              <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-3">
                                <p className="text-slate-400 text-xs">{translateText('Duration')}</p>
                                <p className="text-white font-semibold">{browserDynResult.duration}s</p>
                              </div>
                              <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-3">
                                <p className="text-slate-400 text-xs">{translateText('Outgoing Hosts')}</p>
                                <p className="text-white font-semibold">{browserDynResult.outgoingHosts.length}</p>
                              </div>
                            </div>

                            <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                              <p className="text-white font-medium mb-2">{translateText('Fast Dynamic Summary')}</p>
                              <ul className="space-y-1">
                                {browserDynResult.summary.slice(0, 8).map((item, idx) => (
                                  <li key={idx} className="text-sm text-slate-300">- {item}</li>
                                ))}
                              </ul>
                            </div>

                            <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
                              <div className="space-y-3">
                                <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                                  <p className="text-white font-medium mb-2">{translateText('Redirect Chain')}</p>
                                  {browserDynResult.redirectChain.length === 0 ? (
                                    <p className="text-sm text-slate-400">{translateText('No redirects observed.')}</p>
                                  ) : (
                                    <div className="space-y-2">
                                      {browserDynResult.redirectChain.map((step, idx) => (
                                        <div key={`${step}-${idx}`} className="rounded-lg border border-slate-700 bg-slate-950/70 px-3 py-2 text-sm break-all text-slate-300">
                                          {step}
                                        </div>
                                      ))}
                                    </div>
                                  )}
                                </div>
                                <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                                  <p className="text-white font-medium mb-2">{translateText('Browser Indicators')}</p>
                                  {browserDynResult.indicators.length === 0 ? (
                                    <p className="text-sm text-slate-400">{translateText('No browser-level indicators triggered.')}</p>
                                  ) : (
                                    <div className="flex flex-wrap gap-2">
                                      {browserDynResult.indicators.map((indicator) => (
                                        <span key={indicator} className="rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-xs font-medium text-cyan-200">
                                          {indicator}
                                        </span>
                                      ))}
                                    </div>
                                  )}
                                </div>
                                <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                                  <p className="text-white font-medium mb-2">{translateText('Requests / Responses')}</p>
                                  <p className="text-sm text-slate-300">{browserDynResult.requestCount} {translateText('requests')} / {browserDynResult.responseCount} {translateText('responses')}</p>
                                  <p className="mt-2 text-sm text-slate-400">{translateText('Final URL')}: {browserDynResult.finalUrl || 'N/A'}</p>
                                  <p className="mt-1 text-sm text-slate-400">{translateText('Final Title')}: {browserDynResult.finalTitle || 'N/A'}</p>
                                </div>
                              </div>
                              <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                                <p className="text-white font-medium mb-2">{translateText('Downloads / Dialogs / Errors')}</p>
                                <div className="space-y-3 text-sm">
                                  <div>
                                    <p className="text-slate-400">{translateText('Downloads')}</p>
                                    <p className="text-white">{browserDynResult.downloads.length}</p>
                                  </div>
                                  <div>
                                    <p className="text-slate-400">{translateText('Dialogs')}</p>
                                    <p className="text-white">{browserDynResult.dialogs.length}</p>
                                  </div>
                                  <div>
                                    <p className="text-slate-400">{translateText('Page Errors')}</p>
                                    <p className="text-white">{browserDynResult.pageErrors.length}</p>
                                  </div>
                                  <div>
                                    <p className="text-slate-400">{translateText('Outgoing Hosts')}</p>
                                    <p className="break-words text-slate-300">
                                      {browserDynResult.outgoingHosts.length
                                        ? browserDynResult.outgoingHosts.slice(0, 10).join(', ')
                                        : translateText('No notable outgoing hosts collected.')}
                                    </p>
                                  </div>
                                </div>
                              </div>
                            </div>
                          </div>
                        )}
                      </div>

                      <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-5">
                        <div className="mb-4 flex items-center gap-2 text-cyan-300">
                          <Link2 className="h-4 w-4" />
                          <h4 className="font-semibold text-white">{translateText('Categories')}</h4>
                        </div>
                        <OverviewRow
                          label={translateText('Classifications')}
                          value={
                            technicalDetails.categories.length
                              ? technicalDetails.categories.join(', ')
                              : translateText('No categories available.')
                          }
                        />
                      </div>

                      <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-5">
                        <div className="mb-4 flex items-center gap-2 text-cyan-300">
                          <Clock3 className="h-4 w-4" />
                          <h4 className="font-semibold text-white">{translateText('History')}</h4>
                        </div>
                        <OverviewRow label={translateText('First Submission')} value={formatTimestamp(technicalDetails.history.first_submission)} />
                        <OverviewRow label={translateText('Last Submission')} value={formatTimestamp(technicalDetails.history.last_submission)} />
                        <OverviewRow label={translateText('Last Analysis')} value={formatTimestamp(technicalDetails.history.last_analysis || technicalDetails.static_context.scan_timestamp)} />
                        <OverviewRow label={translateText('Feed First Seen')} value={formatTimestamp(technicalDetails.history.feed_first_seen)} />
                        <OverviewRow label={translateText('Scan Count')} value={String(technicalDetails.history.scan_count ?? 0)} />
                        <OverviewRow label={translateText('Domain Feed Matches')} value={String(technicalDetails.history.domain_feed_matches ?? 0)} />
                      </div>

                      <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-5">
                        <div className="mb-4 flex items-center gap-2 text-cyan-300">
                          <Globe className="h-4 w-4" />
                          <h4 className="font-semibold text-white">{translateText('Domain Info')}</h4>
                        </div>
                        <OverviewRow label={translateText('Host')} value={technicalDetails.domain_info.host || 'N/A'} />
                        <OverviewRow label={translateText('Registered Domain')} value={technicalDetails.domain_info.registered_domain || 'N/A'} />
                        <OverviewRow label={translateText('Registrar')} value={technicalDetails.domain_info.registrar || 'N/A'} />
                        <OverviewRow label={translateText('Registry Country')} value={technicalDetails.domain_info.registry_country || 'N/A'} />
                        <OverviewRow label={translateText('Abuse Contact')} value={technicalDetails.domain_info.abuse_contact || 'N/A'} />
                        <OverviewRow label={translateText('Created')} value={formatTimestamp(technicalDetails.domain_info.created_at)} />
                        <OverviewRow label={translateText('Updated')} value={formatTimestamp(technicalDetails.domain_info.updated_at)} />
                        <OverviewRow label={translateText('Expires')} value={formatTimestamp(technicalDetails.domain_info.expires_at)} />
                        <OverviewRow label={translateText('DNS Records')} value={formatJoinedList(technicalDetails.domain_info.dns_addresses)} />
                        <OverviewRow label={translateText('Nameservers')} value={formatJoinedList(technicalDetails.domain_info.nameservers)} />
                        <OverviewRow label={translateText('WHOIS / RDAP Source')} value={technicalDetails.domain_info.rdap_source || 'N/A'} />
                        <OverviewRow
                          label={translateText('WHOIS Status')}
                          value={technicalDetails.domain_info.rdap_error || translateText('Domain metadata collected successfully.')}
                        />
                      </div>

                      <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-5">
                        <div className="mb-4 flex items-center gap-2 text-cyan-300">
                          <Server className="h-4 w-4" />
                          <h4 className="font-semibold text-white">{translateText('Request Summary')}</h4>
                        </div>
                        <OverviewRow label={translateText('Final URL')} value={technicalDetails.http_response.final_url || 'N/A'} />
                        <OverviewRow label={translateText('Serving IP Address')} value={technicalDetails.http_response.serving_ip_address || 'N/A'} />
                        <OverviewRow label={translateText('Status Code')} value={String(technicalDetails.http_response.status_code ?? 'N/A')} />
                        <OverviewRow label={translateText('Body Length')} value={formatBytes(technicalDetails.http_response.body_length)} />
                        <OverviewRow label={translateText('Fetched At')} value={formatTimestamp(technicalDetails.http_response.fetched_at)} />
                        <OverviewRow
                          label={translateText('TLS Validity')}
                          value={
                            technicalDetails.http_response.tls?.available
                              ? `${technicalDetails.http_response.tls.valid_from || 'N/A'} -> ${technicalDetails.http_response.tls.valid_to || 'N/A'}`
                              : translateText('No TLS certificate collected for this URL.')
                          }
                        />
                      </div>

                      <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-5">
                        <div className="mb-4 flex items-center justify-between gap-4">
                          <div>
                            <h4 className="font-semibold text-white">{translateText('Website Screenshot')}</h4>
                            <p className="text-sm text-slate-400">
                              {browserDynResult?.screenshots?.length
                                ? translateText('Shows screenshots captured by the fast browser dynamic scan. You can still capture a direct static screenshot manually if needed.')
                                : translateText('Captures a normal browser screenshot of the scanned page without starting the sandbox.')}
                            </p>
                          </div>
                          <div className="flex items-center gap-2">
                            {!browserDynResult?.screenshots?.length && showWebsitePreview && (
                              <button
                                type="button"
                                onClick={() => void loadWebsiteScreenshot(true)}
                                disabled={websiteScreenshotLoading}
                                className="rounded-lg border border-slate-600 bg-slate-900/50 px-4 py-2 text-sm font-medium text-slate-200 transition hover:border-cyan-500/40 hover:text-cyan-200 disabled:opacity-60"
                              >
                                {websiteScreenshotLoading ? translateText('Capturing...') : translateText('Refresh Screenshot')}
                              </button>
                            )}
                            <button
                              type="button"
                              onClick={() => {
                                const next = !showWebsitePreview;
                                setShowWebsitePreview(next);
                                if (next && !browserDynResult?.screenshots?.length) {
                                  void loadWebsiteScreenshot(false);
                                }
                              }}
                              className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-200 transition hover:bg-cyan-500/20"
                            >
                              {showWebsitePreview ? translateText('Hide Screenshot') : translateText('Show Screenshot')}
                            </button>
                          </div>
                        </div>
                        {showWebsitePreview ? (
                          <div className="space-y-3">
                            <div className="overflow-hidden rounded-xl border border-slate-700 bg-slate-950">
                              {browserDynResult?.screenshots?.length ? (
                                <div className="space-y-3 p-3">
                                  {browserDynResult.screenshots.map((shot) => (
                                    <div key={shot.label} className="rounded-lg border border-slate-700 bg-slate-950/70 p-2">
                                      <p className="mb-2 text-xs uppercase tracking-[0.18em] text-slate-500">{shot.label}</p>
                                      <img src={shot.image} alt={shot.label} className="w-full rounded" />
                                    </div>
                                  ))}
                                </div>
                              ) : websiteScreenshotLoading && !websiteScreenshotUrl ? (
                                <div className="flex h-[560px] items-center justify-center gap-3 text-slate-300">
                                  <Loader2 className="h-5 w-5 animate-spin text-cyan-400" />
                                  <span>{translateText('Capturing website screenshot...')}</span>
                                </div>
                              ) : websiteScreenshotError ? (
                                <div className="flex min-h-[220px] items-center justify-center p-6 text-center text-sm text-red-300">
                                  {websiteScreenshotError}
                                </div>
                              ) : websiteScreenshotUrl ? (
                                <img
                                  src={websiteScreenshotUrl}
                                  alt="Website screenshot"
                                  className="h-auto w-full object-contain"
                                />
                              ) : (
                                <div className="flex min-h-[220px] items-center justify-center p-6 text-center text-sm text-slate-400">
                                  {translateText('No screenshot captured yet.')}
                                </div>
                              )}
                            </div>
                            <a
                              href={technicalDetails.http_response.final_url || result.details.url}
                              target="_blank"
                              rel="noreferrer"
                              className="inline-flex items-center gap-2 text-sm text-cyan-300 hover:text-cyan-200"
                            >
                              {translateText('Open target in a separate tab')}
                            </a>
                          </div>
                        ) : (
                          <p className="text-sm text-slate-400">{translateText('Use the screenshot button to capture a rendered image of the current website.')}</p>
                        )}
                      </div>
                    </>
                  ) : null}
                </div>
              ) : (
                <div className="space-y-6">
                  <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
                    <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-5">
                      <div className="mb-3 flex items-center gap-2 text-cyan-300">
                        <Link2 className="h-4 w-4" />
                        <h4 className="font-semibold text-white">{translateText('Categories')}</h4>
                      </div>
                      {technicalDetailsLoading && !technicalDetails ? (
                        <div className="flex items-center gap-2 text-slate-300">
                          <Loader2 className="h-4 w-4 animate-spin text-cyan-400" />
                          <span>{translateText('Loading technical details...')}</span>
                        </div>
                      ) : technicalDetails?.categories?.length ? (
                        <div className="flex flex-wrap gap-2">
                          {technicalDetails.categories.map((category, idx) => (
                            <span key={`${category}-${idx}`} className="rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-xs font-medium text-cyan-200">
                              {category}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <p className="text-sm text-slate-400">{translateText('No categories available for this URL yet.')}</p>
                      )}
                    </div>

                    <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-5 xl:col-span-2">
                      <div className="mb-3 flex items-center justify-between gap-3">
                        <div className="flex items-center gap-2 text-cyan-300">
                          <Clock3 className="h-4 w-4" />
                          <h4 className="font-semibold text-white">{translateText('History')}</h4>
                        </div>
                        <button
                          type="button"
                          onClick={() => void loadTechnicalDetails(true)}
                          disabled={technicalDetailsLoading}
                          className="inline-flex items-center gap-2 rounded-lg border border-slate-600 bg-slate-900/50 px-3 py-1.5 text-sm text-slate-200 transition hover:border-cyan-500/40 hover:text-cyan-200 disabled:opacity-60"
                        >
                          <RefreshCw className={`h-4 w-4 ${technicalDetailsLoading ? 'animate-spin' : ''}`} />
                          {translateText('Refresh')}
                        </button>
                      </div>

                      {technicalDetailsError ? (
                        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
                          {technicalDetailsError}
                        </div>
                      ) : (
                        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
                          <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('First Submission')}</p>
                            <p className="mt-2 text-sm text-white">{formatTimestamp(technicalDetails?.history?.first_submission)}</p>
                          </div>
                          <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('Last Submission')}</p>
                            <p className="mt-2 text-sm text-white">{formatTimestamp(technicalDetails?.history?.last_submission)}</p>
                          </div>
                          <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('Last Analysis')}</p>
                            <p className="mt-2 text-sm text-white">{formatTimestamp(technicalDetails?.history?.last_analysis || technicalDetails?.static_context?.scan_timestamp)}</p>
                          </div>
                          <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('Feed First Seen')}</p>
                            <p className="mt-2 text-sm text-white">{formatTimestamp(technicalDetails?.history?.feed_first_seen)}</p>
                          </div>
                          <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('Scan Count')}</p>
                            <p className="mt-2 text-sm font-semibold text-white">{technicalDetails?.history?.scan_count ?? 0}</p>
                          </div>
                          <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('Domain Feed Matches')}</p>
                            <p className="mt-2 text-sm font-semibold text-white">{technicalDetails?.history?.domain_feed_matches ?? 0}</p>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-6">
                    <div className="mb-4 flex items-center gap-2 text-cyan-300">
                      <Globe className="h-4 w-4" />
                      <h4 className="font-semibold text-white">{translateText('Domain Info')}</h4>
                    </div>

                    {technicalDetailsLoading && !technicalDetails ? (
                      <div className="flex items-center gap-2 text-slate-300">
                        <Loader2 className="h-4 w-4 animate-spin text-cyan-400" />
                        <span>{translateText('Loading technical details...')}</span>
                      </div>
                    ) : (
                      <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
                        <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                          <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('Registered Domain')}</p>
                          <p className="mt-2 break-all text-sm text-white">{technicalDetails?.domain_info?.registered_domain || 'N/A'}</p>
                        </div>
                        <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                          <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('Registrar')}</p>
                          <p className="mt-2 break-words text-sm text-white">{technicalDetails?.domain_info?.registrar || 'N/A'}</p>
                        </div>
                        <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                          <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('Registry Country')}</p>
                          <p className="mt-2 text-sm text-white">{technicalDetails?.domain_info?.registry_country || 'N/A'}</p>
                        </div>
                        <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                          <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('Abuse Contact')}</p>
                          <p className="mt-2 break-words text-sm text-white">{technicalDetails?.domain_info?.abuse_contact || 'N/A'}</p>
                        </div>
                        <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                          <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('Created')}</p>
                          <p className="mt-2 text-sm text-white">{formatTimestamp(technicalDetails?.domain_info?.created_at)}</p>
                        </div>
                        <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                          <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('Updated')}</p>
                          <p className="mt-2 text-sm text-white">{formatTimestamp(technicalDetails?.domain_info?.updated_at)}</p>
                        </div>
                        <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                          <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('Expires')}</p>
                          <p className="mt-2 text-sm text-white">{formatTimestamp(technicalDetails?.domain_info?.expires_at)}</p>
                        </div>
                        <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                          <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('WHOIS / RDAP Source')}</p>
                          <p className="mt-2 break-all text-sm text-white">{technicalDetails?.domain_info?.rdap_source || 'N/A'}</p>
                        </div>
                        <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4 xl:col-span-2">
                          <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('DNS Presentation')}</p>
                          {technicalDetails?.domain_info?.dns_addresses?.length ? (
                            <div className="mt-2 flex flex-wrap gap-2">
                              {technicalDetails.domain_info.dns_addresses.map((ip) => (
                                <span key={ip} className="rounded-full border border-slate-600 bg-slate-950/70 px-3 py-1 font-mono text-xs text-slate-200">
                                  {ip}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <p className="mt-2 text-sm text-slate-400">{translateText('No DNS addresses collected.')}</p>
                          )}
                        </div>
                        <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4 xl:col-span-2">
                          <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('Nameservers')}</p>
                          <p className="mt-2 break-words text-sm text-white">{formatJoinedList(technicalDetails?.domain_info?.nameservers)}</p>
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-6">
                    <div className="mb-4 flex items-center gap-2 text-cyan-300">
                      <Server className="h-4 w-4" />
                      <h4 className="font-semibold text-white">{translateText('HTTP Response')}</h4>
                    </div>

                    {technicalDetailsLoading && !technicalDetails ? (
                      <div className="flex items-center gap-2 text-slate-300">
                        <Loader2 className="h-4 w-4 animate-spin text-cyan-400" />
                        <span>{translateText('Loading technical details...')}</span>
                      </div>
                    ) : technicalDetails?.http_response?.error ? (
                      <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-4 text-sm text-yellow-200">
                        {technicalDetails.http_response.error}
                      </div>
                    ) : (
                      <div className="space-y-4">
                        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
                          <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('Final URL')}</p>
                            <p className="mt-2 break-all text-sm text-white">{technicalDetails?.http_response?.final_url || 'N/A'}</p>
                          </div>
                          <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('Serving IP Address')}</p>
                            <p className="mt-2 text-sm text-white">{technicalDetails?.http_response?.serving_ip_address || 'N/A'}</p>
                          </div>
                          <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('Status Code')}</p>
                            <p className="mt-2 text-sm font-semibold text-white">{technicalDetails?.http_response?.status_code ?? 'N/A'}</p>
                          </div>
                          <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('Body Length')}</p>
                            <p className="mt-2 text-sm text-white">{formatBytes(technicalDetails?.http_response?.body_length)}</p>
                          </div>
                        </div>

                        <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
                          <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('Page Title')}</p>
                            <p className="mt-2 break-words text-sm text-white">{technicalDetails?.http_response?.page_title || 'N/A'}</p>
                          </div>
                          <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{translateText('Body SHA-256')}</p>
                            <p className="mt-2 break-all font-mono text-sm text-white">{technicalDetails?.http_response?.body_sha256 || 'N/A'}</p>
                          </div>
                        </div>

                        <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                          <div className="mb-3 flex items-center gap-2 text-cyan-300">
                            <FileText className="h-4 w-4" />
                            <h5 className="font-medium text-white">{translateText('Headers')}</h5>
                          </div>
                          {technicalDetails?.http_response?.headers?.length ? (
                            <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                              {technicalDetails.http_response.headers.map((header) => (
                                <div key={`${header.name}-${header.value}`} className="rounded-lg border border-slate-700 bg-slate-950/70 px-3 py-2 text-sm">
                                  <p className="font-mono text-cyan-200">{header.name}</p>
                                  <p className="mt-1 break-all text-slate-300">{header.value}</p>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p className="text-sm text-slate-400">{translateText('No response headers collected.')}</p>
                          )}
                        </div>

                        <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
                          <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                            <h5 className="mb-3 font-medium text-white">{translateText('DNS Resolution')}</h5>
                            {technicalDetails?.http_response?.resolved_ips?.length ? (
                              <div className="flex flex-wrap gap-2">
                                {technicalDetails.http_response.resolved_ips.map((ip) => (
                                  <span key={ip} className="rounded-full border border-slate-600 bg-slate-950/70 px-3 py-1 font-mono text-xs text-slate-200">
                                    {ip}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <p className="text-sm text-slate-400">{translateText('No DNS addresses collected.')}</p>
                            )}
                          </div>

                          <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                            <h5 className="mb-3 font-medium text-white">{translateText('Redirect Chain')}</h5>
                            {technicalDetails?.http_response?.redirect_chain?.length ? (
                              <div className="space-y-2">
                                {technicalDetails.http_response.redirect_chain.map((step, idx) => (
                                  <div key={`${step.location}-${idx}`} className="rounded-lg border border-slate-700 bg-slate-950/70 px-3 py-2 text-sm">
                                    <p className="text-cyan-200">{step.status_code}</p>
                                    <p className="mt-1 break-all text-slate-300">{step.location}</p>
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <p className="text-sm text-slate-400">{translateText('No redirects observed.')}</p>
                            )}
                          </div>
                        </div>

                        <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
                          <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                            <h5 className="mb-3 font-medium text-white">{translateText('TLS Certificate')}</h5>
                            {technicalDetails?.http_response?.tls?.available ? (
                              <div className="space-y-2 text-sm">
                                <div>
                                  <p className="text-slate-400">{translateText('Subject')}</p>
                                  <p className="break-words text-white">{technicalDetails.http_response.tls.subject || 'N/A'}</p>
                                </div>
                                <div>
                                  <p className="text-slate-400">{translateText('Issuer')}</p>
                                  <p className="break-words text-white">{technicalDetails.http_response.tls.issuer || 'N/A'}</p>
                                </div>
                                <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                                  <div>
                                    <p className="text-slate-400">{translateText('Valid From')}</p>
                                    <p className="text-white">{technicalDetails.http_response.tls.valid_from || 'N/A'}</p>
                                  </div>
                                  <div>
                                    <p className="text-slate-400">{translateText('Valid To')}</p>
                                    <p className="text-white">{technicalDetails.http_response.tls.valid_to || 'N/A'}</p>
                                  </div>
                                </div>
                              </div>
                            ) : (
                              <p className="text-sm text-slate-400">
                                {technicalDetails?.http_response?.tls?.error || translateText('No TLS certificate collected for this URL.')}
                              </p>
                            )}
                          </div>

                          <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                            <h5 className="mb-3 font-medium text-white">{translateText('Outgoing Links')}</h5>
                            {technicalDetails?.http_response?.outgoing_links?.length ? (
                              <div className="space-y-2">
                                {technicalDetails.http_response.outgoing_links.slice(0, 12).map((link) => (
                                  <div key={link} className="rounded-lg border border-slate-700 bg-slate-950/70 px-3 py-2 text-sm break-all text-slate-300">
                                    {link}
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <p className="text-sm text-slate-400">{translateText('No outgoing links extracted from the fetched page.')}</p>
                            )}
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
