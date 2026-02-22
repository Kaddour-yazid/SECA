import { useEffect, useMemo, useState } from 'react';
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
  Sparkles,
  BarChart3,
  TrendingUp,
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

const pickRandom = (items: string[]): string => {
  if (!items.length) return '';
  return items[Math.floor(Math.random() * items.length)];
};

export function URLScannerView() {
  const { user, token } = useAuth();
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [previousResult, setPreviousResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [currentLayer, setCurrentLayer] = useState(0);
  const [feedStats, setFeedStats] = useState<ThreatFeedStats | null>(null);
  const [hookFact, setHookFact] = useState('Security fact: every URL is checked through four independent risk layers.');

  const layerIcons = [Lock, Database, Shield, Eye];
  const layerNames = ['Format Validation', 'Threat Feed Lookup', 'Domain Reputation', 'Content Analysis'];

  const layer1 = result?.details?.layers?.layer1_format || {};
  const layer2 = result?.details?.layers?.layer2_phishtank || {};
  const layer3 = result?.details?.layers?.layer3_reputation || {};
  const layer4 = result?.details?.layers?.layer4_content || {};

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
        const res = await fetch('http://127.0.0.1:8000/threat-feed/stats', {
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

    try {
      new URL(url);

      for (let i = 1; i <= 4; i++) {
        setCurrentLayer(i);
        await new Promise((resolve) => setTimeout(resolve, 600));
      }

      const formData = new URLSearchParams({ url });

      const res = await fetch('http://127.0.0.1:8000/url-scan-advanced', {
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
    } catch (err) {
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
    <div className="flex-1 bg-slate-900 overflow-hidden flex flex-col h-full">
      <style>{`
        .global-scroll::-webkit-scrollbar { width: 14px; }
        .global-scroll::-webkit-scrollbar-track { background: #1e293b; }
        .global-scroll::-webkit-scrollbar-thumb { background: #475569; border-radius: 7px; border: 3px solid #1e293b; }
        .global-scroll::-webkit-scrollbar-thumb:hover { background: #64748b; }
        .global-scroll { scrollbar-width: thin; scrollbar-color: #475569 #1e293b; }
      `}</style>

      <div className="p-8 pb-4 flex-shrink-0">
        <h2 className="text-3xl font-bold text-white mb-2">Advanced URL Scanner</h2>
        <p className="text-slate-400 mb-4">4-layer security analysis for comprehensive threat detection</p>
      </div>

      <div className="overflow-y-auto px-8 pb-8 global-scroll" style={{ height: 'calc(100vh - 180px)' }}>
        <div className="max-w-4xl mx-auto space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2 bg-slate-800/50 border border-slate-700 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-3 text-cyan-300">
                <Shield className="w-4 h-4" />
                <p className="text-sm font-semibold">URL Analysis Layers</p>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
                  <p className="text-slate-400">Layer 1</p>
                  <p className="text-white font-semibold">Format Validation</p>
                  <p className="text-slate-500 text-xs mt-1">Protocol, syntax, suspicious patterns</p>
                </div>
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
                  <p className="text-slate-400">Layer 2</p>
                  <p className="text-white font-semibold">Threat Feed Lookup</p>
                  <p className="text-slate-500 text-xs mt-1">Known malicious URL/domain match</p>
                </div>
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
                  <p className="text-slate-400">Layer 3</p>
                  <p className="text-white font-semibold">Domain Reputation</p>
                  <p className="text-slate-500 text-xs mt-1">Trust score and domain risk checks</p>
                </div>
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
                  <p className="text-slate-400">Layer 4</p>
                  <p className="text-white font-semibold">Content Analysis</p>
                  <p className="text-slate-500 text-xs mt-1">Indicators and behavior scoring</p>
                </div>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mt-3 text-sm">
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
                  <p className="text-slate-400">Malicious URLs</p>
                  <p className="text-white font-bold text-lg">{feedStats ? feedStats.total_threat_urls.toLocaleString() : '...'}</p>
                </div>
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
                  <p className="text-slate-400">Verified URLs</p>
                  <p className="text-emerald-400 font-bold text-lg">{feedStats ? feedStats.verified_threat_urls.toLocaleString() : '...'}</p>
                </div>
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
                  <p className="text-slate-400">Malicious Domains</p>
                  <p className="text-cyan-300 font-bold text-lg">{feedStats ? feedStats.unique_domains.toLocaleString() : '...'}</p>
                </div>
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
                  <p className="text-slate-400">Platform Scans</p>
                  <p className="text-white font-bold text-lg">{feedStats ? feedStats.scan_totals.total.toLocaleString() : '...'}</p>
                </div>
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
                  <p className="text-slate-400">Malicious Verdicts</p>
                  <p className="text-red-400 font-bold text-lg">{feedStats ? feedStats.scan_totals.malicious.toLocaleString() : '...'}</p>
                </div>
              </div>
            </div>
            <div className="bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border border-cyan-500/30 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2 text-cyan-300">
                <Sparkles className="w-4 h-4" />
                <p className="text-sm font-semibold">Did You Know?</p>
              </div>
              <p className="text-slate-200 text-sm leading-relaxed">{hookFact}</p>
            </div>
          </div>

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
                      <Icon className={`w-6 h-6 mx-auto mb-2 ${active || done ? 'text-cyan-400' : 'text-slate-500'}`} />
                      <p className={`text-sm font-medium ${active || done ? 'text-white' : 'text-slate-500'}`}>Layer {idx + 1}</p>
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

          {error && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 mb-6">
              <div className="flex items-center gap-2 text-red-400">
                <AlertCircle className="w-5 h-5" />
                <p className="font-medium">{error}</p>
              </div>
            </div>
          )}

          {result && !scanning && (
            <div className="space-y-6">
              <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-8 text-center">
                <div className="flex justify-center mb-4">{getStatusIcon()}</div>
                <h3 className="text-2xl font-bold text-white mb-2">Scan Complete</h3>
                <span className={`inline-block px-4 py-2 rounded-full text-sm font-semibold border ${getStatusColor(result.status)}`}>
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
                    <span className="text-white font-bold text-xl min-w-[3rem]">{result.details.overall_threat_score}/100</span>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                  <div className="flex items-center gap-2 mb-4">
                    <BarChart3 className="w-4 h-4 text-cyan-400" />
                    <h4 className="text-white font-semibold">Verdict Breakdown</h4>
                  </div>
                  <div className="space-y-3">
                    {scoreBreakdown?.map((item) => (
                      <div key={item.label} className="flex items-center justify-between rounded-lg bg-slate-900/50 border border-slate-700 p-3">
                        <div>
                          <p className="text-white text-sm font-medium">{item.label}</p>
                          <p className="text-slate-500 text-xs">{item.detail}</p>
                        </div>
                        <p className="text-cyan-300 font-semibold">+{item.score}</p>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                  <div className="flex items-center gap-2 mb-4">
                    <TrendingUp className="w-4 h-4 text-cyan-400" />
                    <h4 className="text-white font-semibold">Scan Comparison</h4>
                  </div>
                  {previousResult ? (
                    <div className="space-y-3">
                      <div className="rounded-lg bg-slate-900/50 border border-slate-700 p-3">
                        <p className="text-slate-400 text-sm">Previous score</p>
                        <p className="text-white font-semibold">{previousResult.details.overall_threat_score}/100</p>
                      </div>
                      <div className="rounded-lg bg-slate-900/50 border border-slate-700 p-3">
                        <p className="text-slate-400 text-sm">Delta</p>
                        <p className={`font-semibold ${
                          (previousDelta ?? 0) > 0 ? 'text-red-400' : (previousDelta ?? 0) < 0 ? 'text-green-400' : 'text-slate-300'
                        }`}>
                          {previousDelta === null ? '0' : `${previousDelta > 0 ? '+' : ''}${previousDelta}`}
                        </p>
                      </div>
                    </div>
                  ) : (
                    <div className="rounded-lg bg-slate-900/50 border border-slate-700 p-3">
                      <p className="text-slate-400 text-sm">Run one more scan to unlock comparison insights.</p>
                    </div>
                  )}
                </div>
              </div>

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
                      {layer1.issues.map((issue: string, idx: number) => (
                        <li key={idx} className="text-white text-sm">- {issue}</li>
                      ))}
                    </ul>
                  </div>
                ) : (
                  <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                    <p className="text-green-400">No format issues detected</p>
                  </div>
                )}
              </div>

              <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 bg-cyan-500/10 border border-cyan-500/30 rounded-lg flex items-center justify-center text-cyan-400">
                    <Database className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="text-white font-semibold">Layer 2: Threat Feed Database</h4>
                    <p className="text-slate-400 text-sm">Known malicious URL and domain lookup</p>
                  </div>
                </div>
                {Object.keys(layer2).length > 0 ? (
                  <div className={`rounded-lg p-4 border ${getThreatLevelColor(layer2.threat_level || 'low')}`}>
                    <p className="font-medium mb-2">{layer2.found ? 'Found in Database' : 'Not Found in Database'}</p>
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
                          {layer3.issues.map((issue: string, idx: number) => (
                            <li key={idx} className="text-white text-sm">- {issue}</li>
                          ))}
                        </ul>
                      </div>
                    ) : (
                      <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3">
                        <p className="text-green-400 text-sm">No reputation issues detected</p>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="bg-slate-700/20 border border-slate-600 rounded-lg p-4">
                    <p className="text-slate-300 text-sm">No Layer 3 data returned.</p>
                  </div>
                )}
              </div>

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
                          {layer4.indicators.map((indicator: string, idx: number) => (
                            <li key={idx} className="text-white text-sm">- {indicator}</li>
                          ))}
                        </ul>
                      </div>
                    ) : (
                      <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                        <p className="text-green-400">No suspicious content indicators</p>
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
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
