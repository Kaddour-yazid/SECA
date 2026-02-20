import { useState, useEffect } from 'react';
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

export function URLScannerView() {
  const { user, token } = useAuth();
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [currentLayer, setCurrentLayer] = useState(0);

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

    try {
      new URL(url);

      for (let i = 1; i <= 4; i++) {
        setCurrentLayer(i);
        await new Promise(resolve => setTimeout(resolve, 600));
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


            </div>
          )}
        </div>
      </div>
    </div>
  );
}
