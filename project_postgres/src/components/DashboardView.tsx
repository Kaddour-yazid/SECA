import { useCallback, useEffect, useMemo, useState } from "react";
import { Activity, Shield, AlertTriangle, CheckCircle, X, FileText, Calendar, Gauge } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { apiUrl } from '../config/api';

type DashboardViewProps = {
  isActive?: boolean;
};

type ScanRow = {
  id: number;
  scan_type: string;
  target: string;
  status: string;
  threat_score: number;
  created_at: string;
  details?: string;
};

type ScanStats = {
  total: number;
  clean: number;
  malicious: number;
  suspicious: number;
};

type HighlightTone = 'neutral' | 'good' | 'warn' | 'bad';
type ScanDetailHighlight = {
  label: string;
  value: string;
  tone?: HighlightTone;
};
type ScanDetailSummary = {
  highlights: ScanDetailHighlight[];
  notes: string[];
};

const formatBytes = (bytes: number | undefined): string => {
  if (!Number.isFinite(bytes)) {
    return 'N/A';
  }
  const value = Number(bytes);
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  return `${(value / (1024 * 1024 * 1024)).toFixed(2)} GB`;
};

const safeParseDetails = (raw?: string): any | null => {
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
};

const uniqueStrings = (values: string[]) => [...new Set(values.filter(Boolean))];

const buildDetailSummary = (scan: ScanRow | null): ScanDetailSummary => {
  if (!scan) {
    return { highlights: [], notes: [] };
  }

  const parsed = safeParseDetails(scan.details);
  if (!parsed) {
    return {
      highlights: [
        { label: 'Scan type', value: scan.scan_type || 'Unknown' },
        { label: 'Threat score', value: `${scan.threat_score ?? 0}/100` },
      ],
      notes: ['No structured detail payload available for this scan.'],
    };
  }

  const type = (scan.scan_type || '').toLowerCase();

  if (type.includes('url')) {
    const layer2 = parsed?.layers?.layer2_phishtank ?? {};
    const layer3 = parsed?.layers?.layer3_reputation ?? {};
    const layer4 = parsed?.layers?.layer4_content ?? {};
    const indicators = Array.isArray(layer4?.indicators) ? layer4.indicators : [];
    const reputationScore = Number(layer3?.reputation_score ?? 0);

    return {
      highlights: [
        { label: 'Threat score', value: `${parsed?.overall_threat_score ?? scan.threat_score ?? 0}/100`, tone: scan.status === 'malicious' ? 'bad' : scan.status === 'suspicious' ? 'warn' : 'good' },
        { label: 'Threat feed match', value: layer2?.found ? 'Yes' : 'No', tone: layer2?.found ? 'bad' : 'good' },
        { label: 'Reputation score', value: `${reputationScore}/100`, tone: reputationScore < 40 ? 'bad' : reputationScore < 70 ? 'warn' : 'good' },
        { label: 'Content indicators', value: `${indicators.length}`, tone: indicators.length > 0 ? 'warn' : 'good' },
      ],
      notes: uniqueStrings([
        layer2?.message,
        ...(indicators.slice(0, 3) as string[]),
      ]),
    };
  }

  if (type.includes('email')) {
    const auth = parsed?.authentication ?? {};
    const urls = parsed?.url_analysis ?? {};
    const attachments = parsed?.attachment_analysis ?? {};
    const signals = Array.isArray(parsed?.phishing_signals) ? parsed.phishing_signals : [];
    const authFailures = [auth?.spf, auth?.dkim, auth?.dmarc].filter((value: string) => value === 'fail' || value === 'softfail').length;

    return {
      highlights: [
        { label: 'Threat score', value: `${parsed?.overall_threat_score ?? scan.threat_score ?? 0}/100`, tone: scan.status === 'malicious' ? 'bad' : scan.status === 'suspicious' ? 'warn' : 'good' },
        { label: 'Sender', value: String(parsed?.headers?.from || 'Unknown') },
        { label: 'URLs extracted', value: `${Number(urls?.count ?? 0)}`, tone: Number(urls?.malicious ?? 0) > 0 ? 'bad' : Number(urls?.suspicious ?? 0) > 0 ? 'warn' : 'good' },
        { label: 'Attachments', value: `${Number(attachments?.count ?? 0)}`, tone: Number(attachments?.malicious ?? 0) > 0 ? 'bad' : Number(attachments?.suspicious ?? 0) > 0 ? 'warn' : 'good' },
        { label: 'Auth failures', value: `${authFailures}`, tone: authFailures > 0 ? 'bad' : 'good' },
        { label: 'Phishing signals', value: `${signals.length}`, tone: signals.length > 0 ? 'warn' : 'good' },
      ],
      notes: uniqueStrings([
        parsed?.subject ? `Subject: ${parsed.subject}` : '',
        parsed?.headers?.reply_to && parsed?.headers?.reply_to !== parsed?.headers?.from ? `Reply-To: ${parsed.headers.reply_to}` : '',
        ...signals.slice(0, 3),
      ]),
    };
  }

  if (type.includes('hash')) {
    const detections = Number(parsed?.detections ?? 0);
    const engines = Number(parsed?.engines ?? 0);
    const family = parsed?.malwareFamily && parsed?.malwareFamily !== 'None' ? String(parsed.malwareFamily) : 'None';

    return {
      highlights: [
        { label: 'Hash type', value: String(parsed?.hashType ?? 'Unknown') },
        { label: 'Detections', value: `${detections}/${engines || '?'}`, tone: detections > 0 ? 'bad' : 'good' },
        { label: 'Database match', value: parsed?.found ? 'Yes' : 'No', tone: parsed?.found ? 'warn' : 'good' },
        { label: 'Malware family', value: family, tone: family !== 'None' ? 'bad' : 'good' },
      ],
      notes: uniqueStrings([
        parsed?.firstSeen ? `First seen: ${new Date(parsed.firstSeen).toLocaleString()}` : '',
      ]),
    };
  }

  const layer1 = parsed?.layers?.layer1_info ?? {};
  const layer2 = parsed?.layers?.layer2_hashes ?? {};
  const layer3 = parsed?.layers?.layer3_threats ?? {};
  const layer4 = parsed?.layers?.layer4_code ?? {};
  const threatNames = Array.isArray(layer3?.threats)
    ? layer3.threats.map((t: any) => (typeof t === 'string' ? t : t?.name)).filter(Boolean)
    : [];
  const suspiciousStrings = Array.isArray(layer4?.suspiciousStrings) ? layer4.suspiciousStrings : [];
  const anomalies = Array.isArray(layer4?.anomalies) ? layer4.anomalies : [];
  const codeAlertCount =
    suspiciousStrings.length +
    anomalies.length +
    (layer4?.obfuscated ? 1 : 0) +
    (layer4?.packerDetected ? 1 : 0);

  return {
    highlights: [
      { label: 'File category', value: String(layer1?.riskCategory ?? 'Unknown') },
      { label: 'File size', value: formatBytes(Number(layer1?.fileSize)) },
      { label: 'Entropy', value: Number.isFinite(Number(layer1?.entropy)) ? Number(layer1?.entropy).toFixed(2) : 'N/A', tone: Number(layer1?.entropy) >= 7.2 ? 'warn' : 'neutral' },
      { label: 'Detections', value: `${Number(layer2?.detections ?? 0)}/${Number(layer2?.engines ?? 0) || '?'}`, tone: Number(layer2?.detections ?? 0) > 0 ? 'bad' : 'good' },
      { label: 'Threat indicators', value: `${threatNames.length}`, tone: threatNames.length > 0 ? 'warn' : 'good' },
      { label: 'Code alerts', value: `${codeAlertCount}`, tone: codeAlertCount > 0 ? 'warn' : 'good' },
    ],
    notes: uniqueStrings([
      ...threatNames.slice(0, 3),
      ...suspiciousStrings.slice(0, 2),
      ...anomalies.slice(0, 2),
    ]),
  };
};

const toneClass = (tone: HighlightTone = 'neutral'): string => {
  if (tone === 'good') return 'text-green-300 border-green-500/30 bg-green-500/10';
  if (tone === 'warn') return 'text-yellow-300 border-yellow-500/30 bg-yellow-500/10';
  if (tone === 'bad') return 'text-red-300 border-red-500/30 bg-red-500/10';
  return 'text-slate-200 border-slate-700 bg-slate-800/60';
};

const normalizeScanType = (scanType: string | undefined): { label: string; accentClass: string } => {
  const raw = (scanType || '').toLowerCase();
  if (raw.includes('url')) {
    return { label: 'URL Scanning', accentClass: 'text-violet-300' };
  }
  if (raw.includes('email')) {
    return { label: 'Email Scanning', accentClass: 'text-fuchsia-300' };
  }
  if (raw.includes('file')) {
    return { label: 'File Scanning', accentClass: 'text-cyan-300' };
  }
  if (raw.includes('hash')) {
    return { label: 'Hash Checking', accentClass: 'text-amber-300' };
  }
  if (raw.includes('gateway')) {
    return { label: 'Gateway Monitoring', accentClass: 'text-emerald-300' };
  }
  return { label: 'Security Scan', accentClass: 'text-slate-200' };
};

export function DashboardView({ isActive = true }: DashboardViewProps) {
  const { token } = useAuth();
  const [scans, setScans] = useState<ScanRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<ScanStats>({
    total: 0,
    clean: 0,
    malicious: 0,
    suspicious: 0,
  });
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [selectedScan, setSelectedScan] = useState<ScanRow | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  const fallbackStatsFromScans = (scanRows: ScanRow[]): ScanStats => ({
    total: scanRows.length,
    clean: scanRows.filter((s) => s.status === 'clean').length,
    malicious: scanRows.filter((s) => s.status === 'malicious').length,
    suspicious: scanRows.filter((s) => s.status === 'suspicious').length,
  });

  const loadDashboardData = useCallback(async () => {
    if (!token) {
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      const headers = { Authorization: `Bearer ${token}` };
      const [scansRes, statsRes] = await Promise.all([
        fetch(apiUrl('/scans?limit=500'), { headers, cache: 'no-store' }),
        fetch(apiUrl('/scans/stats'), { headers, cache: 'no-store' }),
      ]);

      if (!scansRes.ok) {
        throw new Error('Failed to fetch dashboard data');
      }
      const scanRows: ScanRow[] = await scansRes.json();
      setScans(scanRows);

      if (statsRes.ok) {
        const statsPayload: ScanStats = await statsRes.json();
        setStats(statsPayload);
      } else {
        setStats(fallbackStatsFromScans(scanRows));
      }

      setLastUpdated(new Date().toLocaleTimeString());
      setError(null);
    } catch (err) {
      console.error("Failed to load dashboard data:", err);
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    if (!isActive || !token) {
      return;
    }

    void loadDashboardData();
    const intervalId = window.setInterval(() => {
      void loadDashboardData();
    }, 10000);

    return () => window.clearInterval(intervalId);
  }, [isActive, token, loadDashboardData]);

  const openScanReport = useCallback(async (scanId: number) => {
    if (!token) {
      return;
    }
    const baseScan = scans.find((s) => s.id === scanId) || null;
    setSelectedScanId(scanId);
    setSelectedScan(baseScan);
    setDetailLoading(true);
    setDetailError(null);
    try {
      const res = await fetch(apiUrl(`/scans/${scanId}`), {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data: ScanRow = await res.json();
        setSelectedScan(data);
        return;
      }

      // Backward-compatible fallback for backend instances that do not expose /scans/{id}
      const fallbackRes = await fetch(apiUrl('/scans?limit=500&include_details=true'), {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (fallbackRes.ok) {
        const fallbackRows: ScanRow[] = await fallbackRes.json();
        const fallbackScan = fallbackRows.find((s) => s.id === scanId) || baseScan;
        setSelectedScan(fallbackScan);
        if (!fallbackScan?.details) {
          setDetailError('Full report details are unavailable on the current backend session.');
        }
      } else {
        setDetailError('Full report details are unavailable on the current backend session.');
      }
    } catch (err) {
      setDetailError(err instanceof Error ? err.message : 'Failed to load scan report');
    } finally {
      setDetailLoading(false);
    }
  }, [token, scans]);

  const closeScanReport = useCallback(() => {
    setSelectedScanId(null);
    setSelectedScan(null);
    setDetailError(null);
    setDetailLoading(false);
  }, []);

  useEffect(() => {
    if (selectedScanId === null) {
      return;
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        closeScanReport();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [selectedScanId, closeScanReport]);

  const selectedSummary = useMemo(() => buildDetailSummary(selectedScan), [selectedScan]);

  return (
    <div className="flex-1 bg-slate-900 global-scroll">
      <style>{`
        @keyframes secaBackdropIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        @keyframes secaModalIn {
          from { opacity: 0; transform: translateY(18px) scale(0.98); }
          to { opacity: 1; transform: translateY(0) scale(1); }
        }
        .seca-backdrop-in { animation: secaBackdropIn 180ms ease-out; }
        .seca-modal-in { animation: secaModalIn 220ms ease-out; }
      `}</style>
      <div className="p-8">
        <div className="flex items-start justify-between mb-8 gap-4">
          <div>
            <h2 className="text-3xl font-bold text-white mb-2">Dashboard</h2>
            <p className="text-slate-400">Overview of your security scans</p>
          </div>
          <div className="text-right">
            <p className="text-xs text-slate-500 mt-2">
              Auto-refresh every 10s
            </p>
            <p className="text-xs text-slate-500 mt-1">
              Last update: {lastUpdated || 'Waiting...'}
            </p>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-slate-400 text-sm font-medium">Total Scans</h3>
              <Activity className="w-5 h-5 text-cyan-400" />
            </div>
            <p className="text-3xl font-bold text-white">{stats.total}</p>
          </div>

          <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-6">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-green-400 text-sm font-medium">Clean</h3>
              <CheckCircle className="w-5 h-5 text-green-400" />
            </div>
            <p className="text-3xl font-bold text-green-400">{stats.clean}</p>
          </div>

          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-6">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-red-400 text-sm font-medium">Malicious</h3>
              <Shield className="w-5 h-5 text-red-400" />
            </div>
            <p className="text-3xl font-bold text-red-400">{stats.malicious}</p>
          </div>

          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-6">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-yellow-400 text-sm font-medium">Suspicious</h3>
              <AlertTriangle className="w-5 h-5 text-yellow-400" />
            </div>
            <p className="text-3xl font-bold text-yellow-400">{stats.suspicious}</p>
          </div>
        </div>

        {/* Recent Scans */}
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4">Recent Scans</h3>

          {loading && (
            <div className="text-center py-8">
              <div className="w-12 h-12 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
              <p className="text-slate-400">Loading scans...</p>
            </div>
          )}

          {error && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
              <p className="text-red-400">{error}</p>
            </div>
          )}

          {!loading && !error && scans.length === 0 && (
            <p className="text-slate-400 text-center py-8">No scans yet</p>
          )}

          {!loading && !error && scans.length > 0 && (
            <ul className="space-y-3">
              {scans.slice(0, 10).map((scan) => {
                const scanType = normalizeScanType(scan.scan_type);
                return (
                  <li
                    key={scan.id}
                    className="bg-slate-900/50 rounded-lg border border-slate-700 hover:border-cyan-500/40 transition"
                  >
                    <button
                      onClick={() => void openScanReport(scan.id)}
                      className="w-full flex items-center justify-between p-4 text-left"
                    >
                      <div className="flex items-center gap-4 min-w-0">
                        <div className={`w-2 h-2 rounded-full ${
                          scan.status === 'clean' ? 'bg-green-400' :
                          scan.status === 'malicious' ? 'bg-red-400' :
                          'bg-yellow-400'
                        }`} />
                        <div className="min-w-0">
                          <p className={`font-bold text-lg leading-tight ${scanType.accentClass}`}>
                            {scanType.label}
                          </p>
                          <p className="text-slate-400 text-sm truncate" title={scan.target || 'N/A'}>
                            {scan.target || 'N/A'}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                          scan.status === 'clean' ? 'bg-green-500/10 text-green-400 border border-green-500/30' :
                          scan.status === 'malicious' ? 'bg-red-500/10 text-red-400 border border-red-500/30' :
                          'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30'
                        }`}>
                          {scan.status || 'Unknown'}
                        </span>
                        <span className="text-slate-500 text-sm">Open report</span>
                      </div>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </div>

      {selectedScanId !== null && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/65 backdrop-blur-sm seca-backdrop-in"
          onClick={closeScanReport}
        >
          <div
            className="w-full max-w-3xl max-h-[90vh] overflow-hidden bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl seca-modal-in"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700">
              <div>
                <h3 className="text-xl font-bold text-white">Scan Report</h3>
                <p className="text-slate-400 text-sm">Detailed report for scan #{selectedScanId}</p>
              </div>
              <button
                onClick={closeScanReport}
                className="w-9 h-9 rounded-lg border border-slate-600 text-slate-300 hover:text-white hover:border-slate-400 flex items-center justify-center transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-6 overflow-y-auto max-h-[75vh]">
              {detailLoading && (
                <div className="text-center py-10">
                  <div className="w-10 h-10 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
                  <p className="text-slate-400">Loading full scan report...</p>
                </div>
              )}

              {!detailLoading && selectedScan && (
                <div className="space-y-4">
                  {detailError && (
                    <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                      <p className="text-yellow-300 text-sm">{detailError}</p>
                    </div>
                  )}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <div className="bg-slate-800/60 border border-slate-700 rounded-lg p-4">
                      <p className="text-slate-400 text-xs mb-1 flex items-center gap-1"><FileText className="w-3 h-3" />Target</p>
                      <p className="text-white font-medium break-all">{selectedScan.target || 'N/A'}</p>
                    </div>
                    <div className="bg-slate-800/60 border border-slate-700 rounded-lg p-4">
                      <p className="text-slate-400 text-xs mb-1 flex items-center gap-1"><Activity className="w-3 h-3" />Type</p>
                      <p className="text-white font-medium">{normalizeScanType(selectedScan.scan_type).label}</p>
                    </div>
                    <div className="bg-slate-800/60 border border-slate-700 rounded-lg p-4">
                      <p className="text-slate-400 text-xs mb-1 flex items-center gap-1"><Calendar className="w-3 h-3" />Created</p>
                      <p className="text-white font-medium">
                        {selectedScan.created_at ? new Date(selectedScan.created_at).toLocaleString() : 'Unknown'}
                      </p>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div className="bg-slate-800/60 border border-slate-700 rounded-lg p-4">
                      <p className="text-slate-400 text-xs mb-2">Verdict</p>
                      <span className={`inline-flex px-3 py-1 rounded-full text-sm font-medium ${
                        selectedScan.status === 'clean' ? 'bg-green-500/10 text-green-400 border border-green-500/30' :
                        selectedScan.status === 'malicious' ? 'bg-red-500/10 text-red-400 border border-red-500/30' :
                        'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30'
                      }`}>
                        {selectedScan.status}
                      </span>
                    </div>
                    <div className="bg-slate-800/60 border border-slate-700 rounded-lg p-4">
                      <p className="text-slate-400 text-xs mb-2 flex items-center gap-1"><Gauge className="w-3 h-3" />Threat score</p>
                      <p className="text-white text-xl font-semibold">{selectedScan.threat_score ?? 0}/100</p>
                    </div>
                  </div>

                  <div className="bg-slate-800/60 border border-slate-700 rounded-lg p-4">
                    <p className="text-slate-300 font-medium mb-3">Analysis Summary</p>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {selectedSummary.highlights.map((item, index) => (
                        <div key={`${item.label}-${index}`} className={`rounded-lg border px-3 py-2 ${toneClass(item.tone)}`}>
                          <p className="text-xs opacity-80 mb-1">{item.label}</p>
                          <p className="text-sm font-semibold">{item.value}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="bg-slate-800/60 border border-slate-700 rounded-lg p-4">
                    <p className="text-slate-300 font-medium mb-2">Key Findings</p>
                    {selectedSummary.notes.length > 0 ? (
                      <ul className="space-y-2">
                        {selectedSummary.notes.map((note, index) => (
                          <li key={`${note}-${index}`} className="text-sm text-slate-300">
                            - {note}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-slate-400 text-sm">No important warnings found in this report.</p>
                    )}
                  </div>
                </div>
              )}

              {!detailLoading && !selectedScan && (
                <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
                  <p className="text-red-300 text-sm">Unable to load scan report data.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
