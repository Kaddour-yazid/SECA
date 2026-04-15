import { useState, useEffect, useRef } from 'react';
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
  Monitor,
  FolderOpen,
  Settings,
  ChevronDown,
  ChevronUp,
  XCircle,
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

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

type DynamicProcess = { pid: number; name: string; action: string; suspicious: boolean };
type DynamicNetwork = { protocol: string; destination: string; port: number; suspicious: boolean };
type DynamicFile = { path: string; action: 'created' | 'modified' | 'deleted'; suspicious: boolean };
type DynamicRegistry = { key: string; action: 'read' | 'write' | 'delete'; suspicious: boolean };

type DynamicResult = {
  verdict: 'clean' | 'malicious' | 'suspicious';
  threatScore: number;
  duration: number;
  processes: DynamicProcess[];
  network: DynamicNetwork[];
  files: DynamicFile[];
  registry: DynamicRegistry[];
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
};

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000').trim().replace(/\/+$/, '');
const apiUrl = (path: string) => `${API_BASE_URL}${path.startsWith('/') ? path : `/${path}`}`;

export function URLScannerView() {
  const { user, token, signOut } = useAuth();
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [currentLayer, setCurrentLayer] = useState(0);
  const [dynState, setDynState] = useState<'idle' | 'running' | 'done' | 'error'>('idle');
  const [dynStep, setDynStep] = useState('');
  const [dynProgress, setDynProgress] = useState(0);
  const [dynResult, setDynResult] = useState<DynamicResult | null>(null);
  const [dynError, setDynError] = useState<string | null>(null);
  const [dynJobId, setDynJobId] = useState<string | null>(null);
  const [dynCancelling, setDynCancelling] = useState(false);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({
    processes: true,
    network: true,
    files: true,
    registry: true,
  });
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const pollGenerationRef = useRef(0);
  const activePollJobRef = useRef<string | null>(null);
  const pollAbortRef = useRef<AbortController | null>(null);

  // Log the result to verify backend data
  useEffect(() => {
    if (result) {
      console.log('✅ Scan result from backend:', result);
    }
  }, [result]);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url || !user || !token) {
      setError('Please login and enter a valid URL');
      return;
    }

    setScanning(true);
    setResult(null);
    setError(null);
    setCurrentLayer(0);
    clearPoll();
    setDynState('idle');
    setDynStep('');
    setDynProgress(0);
    setDynResult(null);
    setDynError(null);
    setDynJobId(null);
    setDynCancelling(false);

    try {
      new URL(url);

      for (let i = 1; i <= 4; i++) {
        setCurrentLayer(i);
        await new Promise(resolve => setTimeout(resolve, 600));
      }

      const formData = new URLSearchParams({ url });

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

      setResult({
        status: data.status || 'clean',
        threat_score: data.threat_score || 0,
        details,
      });
    } catch (err) {
      console.error(err);
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setScanning(false);
      setCurrentLayer(0);
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

  const layerIcons = [Lock, Database, Shield, Eye];
  const layerNames = [
    'Format Validation',
    'PhishTank Database',
    'Domain Reputation',
    'Content Analysis',
  ];

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
            setDynError('Dynamic URL job not found anymore. Start a new run.');
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
          setDynResult(poll.result);
          setDynState('done');
          setDynJobId(null);
          setDynCancelling(false);
          setDynError(null);
        } else if (poll.status === 'error') {
          clearPoll();
          setDynError(poll.error || 'Dynamic URL analysis failed');
          setDynState('error');
          setDynJobId(null);
          setDynCancelling(false);
        } else {
          setDynState('running');
        }
      } catch (pollErr) {
        if (controller.signal.aborted || !isCurrentPoll()) return;
        clearPoll();
        setDynError(pollErr instanceof Error ? pollErr.message : 'Lost connection to backend');
        setDynState('error');
        setDynJobId(null);
        setDynCancelling(false);
      } finally {
        if (pollAbortRef.current === controller) {
          pollAbortRef.current = null;
        }
      }
    };

    void pollOnce();
    pollRef.current = setInterval(() => {
      void pollOnce();
    }, 2000);
  };

  const startDynamicUrlScan = async () => {
    if (!result || !token) return;
    if (result.status === 'malicious') {
      setDynError('Dynamic URL analysis is blocked when static verdict is malicious.');
      setDynState('error');
      return;
    }

    setDynState('running');
    setDynError(null);
    setDynResult(null);
    setDynProgress(5);
    setDynStep('Preparing URL sandbox environment...');
    setDynCancelling(false);

    try {
      const formData = new URLSearchParams({ url: result.details.url || url });
      const startRes = await fetch(apiUrl('/analyze/url/dynamic'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Bearer ${token}`,
        },
        body: formData,
      });

      const payload = await startRes.json().catch(() => ({}));
      if (!startRes.ok) {
        if (startRes.status === 401) {
          signOut();
          throw new Error('Session expired. Please sign in again.');
        }
        if (startRes.status === 409) {
          throw new Error('Another dynamic analysis is already running. Cancel it or wait for completion.');
        }
        if (startRes.status === 422) {
          const detail = payload?.detail;
          if (typeof detail === 'string') throw new Error(detail);
          if (detail?.message) throw new Error(detail.message);
        }
        throw new Error(payload?.detail || payload?.message || `Server error ${startRes.status}`);
      }

      const jobId = String(payload.job_id || '');
      if (!jobId) {
        throw new Error('Backend did not return a URL dynamic job id.');
      }
      setDynJobId(jobId);
      startPolling(jobId, token);
    } catch (err) {
      clearPoll();
      setDynError(err instanceof Error ? err.message : 'Failed to start URL dynamic analysis.');
      setDynState('error');
      setDynJobId(null);
      setDynCancelling(false);
    }
  };

  const cancelDynamic = async () => {
    if (!dynJobId || !token) return;
    setDynCancelling(true);
    try {
      await fetch(apiUrl(`/analyze/url/dynamic/cancel/${dynJobId}`), {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
    } catch {
      // best effort
    } finally {
      clearPoll();
      setDynState('idle');
      setDynResult(null);
      setDynError(null);
      setDynProgress(0);
      setDynStep('');
      setDynJobId(null);
      setDynCancelling(false);
    }
  };

  const toggleExpand = (section: string) => setExpanded((prev) => ({ ...prev, [section]: !prev[section] }));

  useEffect(() => () => { clearPoll(); }, []);

  return (
    <div className="flex-1 bg-slate-900 overflow-hidden flex flex-col h-full">
      <style>{`
        .global-scroll::-webkit-scrollbar {
          width: 14px;
        }
        .global-scroll::-webkit-scrollbar-track {
          background: #1e293b;
        }
        .global-scroll::-webkit-scrollbar-thumb {
          background: #475569;
          border-radius: 7px;
          border: 3px solid #1e293b;
        }
        .global-scroll::-webkit-scrollbar-thumb:hover {
          background: #64748b;
        }
        .global-scroll {
          scrollbar-width: thin;
          scrollbar-color: #475569 #1e293b;
        }
      `}</style>
      {/* Header (fixed) */}
      <div className="p-8 pb-4 flex-shrink-0">
        <h2 className="text-3xl font-bold text-white mb-2">Advanced URL Scanner</h2>
        <p className="text-slate-400 mb-8">4-layer security analysis for comprehensive threat detection</p>
      </div>

      {/* Scrollable area - with fixed height to force scrollbar */}
      <div
        className="overflow-y-auto px-8 pb-8 global-scroll"
        style={{ height: 'calc(100vh - 180px)' }}
      >
        <div className="max-w-4xl mx-auto">
          {/* Input form */}
          <form onSubmit={handleScan} className="flex gap-4 mb-6">
            <div className="flex-1 relative">
              <Globe className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
              <input
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com"
                className="w-full pl-12 pr-4 py-4 bg-slate-900/50 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 transition"
                required
                disabled={scanning}
              />
            </div>
            <button
              type="submit"
              disabled={scanning || !url}
              className="px-8 py-4 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold rounded-lg flex items-center gap-2 hover:from-cyan-600 hover:to-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition"
            >
              <Search className="w-5 h-5" />
              Scan URL
            </button>
          </form>

          {/* Progress indicator */}
          {scanning && (
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 mb-6">
              <div className="grid grid-cols-4 gap-4 mb-4">
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
                      <Icon
                        className={`w-6 h-6 mx-auto mb-2 ${
                          active || done ? 'text-cyan-400' : 'text-slate-500'
                        }`}
                      />
                      <p className={`text-sm font-medium ${active || done ? 'text-white' : 'text-slate-500'}`}>
                        Layer {idx + 1}
                      </p>
                      <p className={`text-xs ${active || done ? 'text-slate-300' : 'text-slate-600'}`}>{name}</p>
                    </div>
                  );
                })}
              </div>
              <div className="text-center">
                <Loader2 className="w-8 h-8 text-cyan-400 animate-spin mx-auto mb-2" />
                <p className="text-slate-300">Analyzing... Layer {currentLayer}/4</p>
              </div>
            </div>
          )}

          {/* Error */}
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

          {/* Results */}
          {result && !scanning && (
            <div className="space-y-6">
              {/* Overall status */}
              <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-8 text-center">
                <div className="flex justify-center mb-4">{getStatusIcon()}</div>
                <h3 className="text-2xl font-bold text-white mb-2">Scan Complete</h3>
                <span
                  className={`inline-block px-4 py-2 rounded-full text-sm font-semibold border ${getStatusColor(
                    result.status
                  )}`}
                >
                  {result.status.toUpperCase()}
                </span>
                <div className="mt-4">
                  <p className="text-slate-400 text-sm mb-2">Overall Threat Score</p>
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
                    <span className="text-white font-bold text-xl min-w-[3rem]">
                      {result.details.overall_threat_score}/100
                    </span>
                  </div>
                </div>
              </div>

              {/* Layer 1 */}
              <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 bg-cyan-500/10 border border-cyan-500/30 rounded-lg flex items-center justify-center text-cyan-400">
                    <Lock className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="text-white font-semibold">Layer 1: Format Validation</h4>
                    <p className="text-slate-400 text-sm">URL structure and syntax analysis</p>
                  </div>
                </div>
                {layer1.issues && layer1.issues.length > 0 ? (
                  <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                    <p className="text-yellow-400 font-medium mb-2">Issues Detected:</p>
                    <ul className="space-y-1">
                      {layer1.issues.map((issue, idx) => (
                        <li key={idx} className="text-white text-sm">
                          • {issue}
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : (
                  <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                    <p className="text-green-400">✓ No format issues detected</p>
                  </div>
                )}
              </div>

              {/* Layer 2 */}
              <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 bg-cyan-500/10 border border-cyan-500/30 rounded-lg flex items-center justify-center text-cyan-400">
                    <Database className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="text-white font-semibold">Layer 2: PhishTank Database</h4>
                    <p className="text-slate-400 text-sm">Known phishing URL database check</p>
                  </div>
                </div>
                {Object.keys(layer2).length > 0 ? (
                  <div
                    className={`rounded-lg p-4 border ${getThreatLevelColor(layer2.threat_level || 'low')}`}
                  >
                    <p className="font-medium mb-2">
                      {layer2.found ? '⚠️ Found in Database' : '✓ Not Found in Database'}
                    </p>
                    <p className="text-sm opacity-90">{layer2.message || 'No additional info'}</p>
                    {layer2.source && <p className="text-sm mt-2 opacity-80">Source: {layer2.source}</p>}
                    {layer2.domain_matches !== undefined && (
                      <p className="text-sm mt-1 opacity-80">Domain matches: {layer2.domain_matches}</p>
                    )}
                  </div>
                ) : (
                  <div className="bg-slate-700/20 border border-slate-600 rounded-lg p-4">
                    <p className="text-slate-300 text-sm">No Layer 2 data returned.</p>
                  </div>
                )}
              </div>

              {/* Layer 3 */}
              <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 bg-cyan-500/10 border border-cyan-500/30 rounded-lg flex items-center justify-center text-cyan-400">
                    <Shield className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="text-white font-semibold">Layer 3: Domain Reputation</h4>
                    <p className="text-slate-400 text-sm">Domain trust and reputation analysis</p>
                  </div>
                </div>
                {Object.keys(layer3).length > 0 ? (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-300">Reputation Score</span>
                      <span className="text-white font-bold">{layer3.reputation_score ?? 0}/100</span>
                    </div>
                    {layer3.issues && layer3.issues.length > 0 ? (
                      <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3">
                        <p className="text-yellow-400 font-medium text-sm mb-2">Reputation Issues:</p>
                        <ul className="space-y-1">
                          {layer3.issues.map((issue, idx) => (
                            <li key={idx} className="text-white text-sm">
                              • {issue}
                            </li>
                          ))}
                        </ul>
                      </div>
                    ) : (
                      <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3">
                        <p className="text-green-400 text-sm">✓ No reputation issues detected</p>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="bg-slate-700/20 border border-slate-600 rounded-lg p-4">
                    <p className="text-slate-300 text-sm">No Layer 3 data returned.</p>
                  </div>
                )}
              </div>

              {/* Layer 4 */}
              <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 bg-cyan-500/10 border border-cyan-500/30 rounded-lg flex items-center justify-center text-cyan-400">
                    <Eye className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="text-white font-semibold">Layer 4: Content Analysis</h4>
                    <p className="text-slate-400 text-sm">Behavioral and content indicators</p>
                  </div>
                </div>
                {Object.keys(layer4).length > 0 ? (
                  <>
                    {layer4.indicators && layer4.indicators.length > 0 ? (
                      <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                        <p className="text-yellow-400 font-medium mb-2">Indicators Found:</p>
                        <ul className="space-y-1">
                          {layer4.indicators.map((indicator, idx) => (
                            <li key={idx} className="text-white text-sm">
                              • {indicator}
                            </li>
                          ))}
                        </ul>
                      </div>
                    ) : (
                      <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                        <p className="text-green-400">✓ No suspicious content indicators</p>
                      </div>
                    )}
                    <div className="mt-3 text-sm text-slate-300 flex items-center justify-between">
                      <span>Content threat score</span>
                      <span className="text-white font-semibold">{layer4.threat_score ?? 0}</span>
                    </div>
                  </>
                ) : (
                  <div className="bg-slate-700/20 border border-slate-600 rounded-lg p-4">
                    <p className="text-slate-300 text-sm">No Layer 4 data returned.</p>
                  </div>
                )}
              </div>

              {/* Dynamic URL Sandbox (Layer 5) */}
              <div className="space-y-4 pt-2">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-purple-500/10 border border-purple-500/30 rounded-lg flex items-center justify-center text-purple-400">
                    <Monitor className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="text-white font-semibold">Layer 5: Dynamic Sandbox</h4>
                    <p className="text-slate-400 text-sm">Isolated runtime behavior analysis (purple dynamic section)</p>
                  </div>
                </div>

                {dynState === 'idle' && (
                  <div className="bg-gradient-to-r from-purple-900/40 to-blue-900/40 border border-purple-500/30 rounded-xl p-6">
                    <div className="flex items-start gap-4">
                      <div className="w-12 h-12 bg-purple-500/20 border border-purple-500/30 rounded-xl flex items-center justify-center flex-shrink-0">
                        <Monitor className="w-6 h-6 text-purple-400" />
                      </div>
                      <div className="flex-1">
                        <h4 className="text-white font-bold text-lg mb-1">Dynamic URL Sandbox Analysis</h4>
                        <p className="text-slate-400 text-sm mb-1">
                          Opens the URL inside an isolated <strong className="text-slate-300">Windows Sandbox VM</strong> and monitors process/network behavior.
                        </p>
                        <p className="text-slate-500 text-xs mb-3">
                          Policy: static malicious URLs are blocked before sandbox launch. Clean/suspicious URLs can run.
                        </p>
                        <div className="flex flex-wrap gap-4 text-xs text-slate-400 mb-4">
                          <span className="flex items-center gap-1"><Monitor className="w-3 h-3" />Process monitoring</span>
                          <span className="flex items-center gap-1"><Globe className="w-3 h-3" />Network traffic</span>
                          <span className="flex items-center gap-1"><FolderOpen className="w-3 h-3" />File system</span>
                          <span className="flex items-center gap-1"><Settings className="w-3 h-3" />Registry</span>
                        </div>
                        {result.status === 'malicious' && (
                          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-2 mb-3 text-red-400 text-xs">
                            URL flagged malicious by static analysis. Sandbox run is blocked.
                          </div>
                        )}
                        <button
                          onClick={startDynamicUrlScan}
                          disabled={result.status === 'malicious'}
                          className="flex items-center gap-2 px-5 py-2.5 bg-purple-600 hover:bg-purple-700 text-white font-semibold rounded-lg transition disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          <Play className="w-4 h-4" /> Run Dynamic Sandbox Analysis
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                {dynState === 'running' && (
                  <div className="bg-slate-800/50 border border-purple-500/30 rounded-xl p-8">
                    <div className="flex items-center justify-between mb-5">
                      <div className="flex items-center gap-3">
                        <Monitor className="w-8 h-8 text-purple-400 animate-pulse" />
                        <div>
                          <h4 className="text-white font-bold">Windows Sandbox Running</h4>
                          <p className="text-slate-500 text-xs">Live progress from backend</p>
                        </div>
                      </div>
                      <button
                        onClick={cancelDynamic}
                        disabled={dynCancelling}
                        className="flex items-center gap-1 text-xs text-slate-500 hover:text-white border border-slate-600 hover:border-slate-400 px-3 py-1.5 rounded-lg transition disabled:opacity-60 disabled:cursor-not-allowed"
                      >
                        <XCircle className="w-3 h-3" /> {dynCancelling ? 'Cancelling...' : 'Cancel'}
                      </button>
                    </div>
                    <div className="bg-slate-900/50 rounded-full h-4 mb-3 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-purple-600 to-blue-500 transition-all duration-700"
                        style={{ width: `${Math.max(dynProgress, 2)}%` }}
                      />
                    </div>
                    <div className="flex items-center justify-between mb-5">
                      <p className="text-purple-300 text-sm font-medium">{dynStep}</p>
                      <span className="text-slate-400 text-sm font-mono">{dynProgress}%</span>
                    </div>
                  </div>
                )}

                {dynState === 'done' && dynResult && (
                  <div className="space-y-4">
                  <div className="bg-slate-800/50 border border-purple-500/30 rounded-xl p-6 text-center">
                    <div className="flex justify-center mb-3">
                      {dynResult.verdict === 'clean' && <CheckCircle className="w-16 h-16 text-green-400" />}
                      {dynResult.verdict === 'suspicious' && <AlertTriangle className="w-16 h-16 text-yellow-400" />}
                      {dynResult.verdict === 'malicious' && <AlertCircle className="w-16 h-16 text-red-400" />}
                    </div>
                    <h4 className="text-white font-bold text-xl mb-2">Dynamic Analysis Complete</h4>
                    <span className={`inline-block px-4 py-2 rounded-full text-sm font-semibold border ${getStatusColor(dynResult.verdict)}`}>
                      {dynResult.verdict.toUpperCase()}
                    </span>
                    <p className="text-slate-400 text-sm mt-2">Execution: {dynResult.duration}s &bull; Dynamic threat score: {dynResult.threatScore}/100</p>
                    <div className="mt-4 text-left bg-slate-900/50 rounded-lg p-4 space-y-1">
                      {dynResult.summary.map((s, i) => <p key={i} className="text-sm text-slate-300">{s}</p>)}
                    </div>
                  </div>

                  {([
                    {
                      key: 'processes', label: 'Process Activity', Icon: Monitor, items: dynResult.processes,
                      empty: '✓ No notable process activity',
                      render: (p: DynamicProcess) => (
                        <div className={`rounded-lg p-3 border text-sm ${p.suspicious ? 'bg-red-500/10 border-red-500/30' : 'bg-slate-900/50 border-slate-600'}`}>
                          <div className="flex items-center gap-2 mb-1">
                            {p.suspicious && <AlertCircle className="w-3 h-3 text-red-400" />}
                            <span className="font-mono text-white">{p.name}</span>
                            <span className="text-slate-500 text-xs">PID: {p.pid}</span>
                            {p.suspicious && <span className="ml-auto text-xs text-red-400 font-medium">SUSPICIOUS</span>}
                          </div>
                          <p className={`text-xs ${p.suspicious ? 'text-red-300' : 'text-slate-400'}`}>{p.action}</p>
                        </div>
                      ),
                    },
                    {
                      key: 'network', label: 'Network Connections', Icon: Globe, items: dynResult.network,
                      empty: '✓ No external network connections',
                      render: (n: DynamicNetwork) => (
                        <div className={`rounded-lg p-3 border text-sm ${n.suspicious ? 'bg-red-500/10 border-red-500/30' : 'bg-slate-900/50 border-slate-600'}`}>
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-white">{n.protocol} → {n.destination}:{n.port}</span>
                            {n.suspicious && <span className="text-xs text-red-400 font-medium">⚠ EXTERNAL</span>}
                          </div>
                        </div>
                      ),
                    },
                    {
                      key: 'files', label: 'File System Changes', Icon: FolderOpen, items: dynResult.files,
                      empty: '✓ No significant file system changes',
                      render: (f: DynamicFile) => (
                        <div className={`rounded-lg p-3 border text-sm ${f.suspicious ? 'bg-yellow-500/10 border-yellow-500/30' : 'bg-slate-900/50 border-slate-600'}`}>
                          <p className="font-mono text-white text-xs break-all">{f.path}</p>
                        </div>
                      ),
                    },
                    {
                      key: 'registry', label: 'Registry Changes', Icon: Settings, items: dynResult.registry,
                      empty: '✓ No registry modifications',
                      render: (r: DynamicRegistry) => (
                        <div className={`rounded-lg p-3 border text-sm ${r.suspicious ? 'bg-red-500/10 border-red-500/30' : 'bg-slate-900/50 border-slate-600'}`}>
                          <p className="font-mono text-white text-xs break-all">{r.key}</p>
                        </div>
                      ),
                    },
                  ] as const).map(({ key, label, Icon, items, render, empty }) => (
                    <div key={key} className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
                      <button
                        onClick={() => toggleExpand(key)}
                        className="w-full flex items-center justify-between p-4 text-white font-semibold hover:bg-slate-700/30 transition"
                      >
                        <div className="flex items-center gap-2">
                          <Icon className="w-4 h-4 text-cyan-400" />{label}
                          <span className="text-slate-500 text-sm font-normal">({items.length})</span>
                        </div>
                        {expanded[key] ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </button>
                      {expanded[key] && (
                        <div className="px-4 pb-4 space-y-2">
                          {items.length === 0
                            ? <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3"><p className="text-green-400 text-sm">{empty}</p></div>
                            : items.map((item, i) => <div key={i}>{render(item)}</div>)}
                        </div>
                      )}
                    </div>
                  ))}

                  <button
                    onClick={() => { setDynState('idle'); setDynResult(null); setDynError(null); }}
                    className="w-full py-3 border border-slate-600 text-slate-400 hover:text-white hover:border-slate-400 rounded-lg transition text-sm"
                  >
                    Run Dynamic Analysis Again
                  </button>
                  </div>
                )}
              </div>

            </div>
          )}
        </div>
      </div>
    </div>
  );
}
