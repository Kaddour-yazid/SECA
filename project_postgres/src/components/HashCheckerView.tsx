import { useState } from 'react';
import {
  Hash,
  AlertCircle,
  CheckCircle,
  AlertTriangle,
  Loader2,
  Search,
  Database,
  ShieldCheck,
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { apiUrl } from '../config/api';

type ScanResultType = {
  status: 'clean' | 'malicious' | 'suspicious';
  threatScore: number;
  details: {
    hash: string;
    hashType: string;
    found: boolean;
    detections: number;
    engines: number;
    malwareFamily: string;
    firstSeen?: string | null;
    sources?: string[];
    evidence?: string[];
    knownGoodMatch?: boolean;
    knownGoodName?: string | null;
    knownGoodProduct?: string | null;
  };
};

export function HashCheckerView() {
  const { user, token } = useAuth();
  const [hash, setHash] = useState('');
  const [hashType, setHashType] = useState<'MD5' | 'SHA1' | 'SHA256'>('SHA256');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResultType | null>(null);
  const [error, setError] = useState<string | null>(null);

  const validateHash = (hashValue: string, type: string): boolean => {
    const hashLengths = {
      MD5: 32,
      SHA1: 40,
      SHA256: 64,
    };
    const hexRegex = /^[a-fA-F0-9]+$/;
    return (
      hashValue.length === hashLengths[type as keyof typeof hashLengths] &&
      hexRegex.test(hashValue)
    );
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!hash || !user || !token) return;

    setScanning(true);
    setResult(null);
    setError(null);

    try {
      if (!validateHash(hash, hashType)) {
        throw new Error(
          `Invalid ${hashType} hash format. Expected ${
            hashType === 'MD5' ? 32 : hashType === 'SHA1' ? 40 : 64
          } hexadecimal characters.`,
        );
      }

      const formData = new URLSearchParams();
      formData.append('scan_type', 'hash');
      formData.append('target', hash.toLowerCase());

      const response = await fetch(apiUrl('/hash-scan'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Bearer ${token}`,
        },
        body: formData,
      });

      if (!response.ok) {
        const errorText = await response.text();
        let errorMessage = 'Hash lookup failed';
        try {
          const errorData = JSON.parse(errorText);
          errorMessage = errorData.detail || errorMessage;
        } catch {
          errorMessage = errorText || errorMessage;
        }
        throw new Error(errorMessage);
      }

      const payload = await response.json();
      setResult({
        status: payload.status,
        threatScore: Number(payload.threat_score ?? 0),
        details: payload.details,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred during scanning');
      setResult(null);
    } finally {
      setScanning(false);
    }
  };

  const getStatusIcon = () => {
    if (!result) return null;
    switch (result.status) {
      case 'clean':
        return <CheckCircle className="h-16 w-16 text-green-400" />;
      case 'malicious':
        return <AlertCircle className="h-16 w-16 text-red-400" />;
      case 'suspicious':
        return <AlertTriangle className="h-16 w-16 text-yellow-400" />;
    }
  };

  const getStatusColor = () => {
    if (!result) return '';
    switch (result.status) {
      case 'clean':
        return 'text-green-400 bg-green-500/10 border-green-500/30';
      case 'malicious':
        return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'suspicious':
        return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
    }
  };

  const renderDetailedResult = () => {
    if (!result) return null;

    if (result.status === 'malicious' && result.details.malwareFamily !== 'None') {
      return (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4">
          <h4 className="mb-2 flex items-center gap-2 font-semibold text-red-400">
            <AlertCircle className="h-5 w-5" />
            Malware Detected
          </h4>
          <div className="space-y-2">
            <div>
              <p className="text-sm text-slate-400">Malware Family</p>
              <p className="font-medium text-white">{result.details.malwareFamily}</p>
            </div>
            {result.details.firstSeen && (
              <div>
                <p className="text-sm text-slate-400">First Seen</p>
                <p className="font-medium text-white">
                  {new Date(result.details.firstSeen).toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric',
                  })}
                </p>
              </div>
            )}
            {result.details.sources && result.details.sources.length > 0 && (
              <div>
                <p className="text-sm text-slate-400">Sources</p>
                <p className="font-medium text-white">{result.details.sources.join(', ')}</p>
              </div>
            )}
          </div>
        </div>
      );
    }

    if (result.details.knownGoodMatch) {
      return (
        <div className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 p-4">
          <h4 className="mb-2 flex items-center gap-2 font-semibold text-cyan-300">
            <ShieldCheck className="h-5 w-5" />
            Known Software Reference
          </h4>
          <div className="space-y-2 text-sm text-slate-300">
            <p>
              This hash matched a known file in CIRCL hashlookup.
            </p>
            {result.details.knownGoodName && (
              <p>
                <span className="text-slate-400">File:</span> {result.details.knownGoodName}
              </p>
            )}
            {result.details.knownGoodProduct && (
              <p>
                <span className="text-slate-400">Product:</span> {result.details.knownGoodProduct}
              </p>
            )}
          </div>
        </div>
      );
    }

    if (result.status === 'suspicious') {
      return (
        <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-4">
          <h4 className="mb-2 flex items-center gap-2 font-semibold text-yellow-400">
            <AlertTriangle className="h-5 w-5" />
            Suspicious Indicators
          </h4>
          <p className="text-sm text-slate-300">
            This hash has suspicious characteristics but no confirmed malware family yet.
          </p>
        </div>
      );
    }

    return (
      <div className="rounded-lg border border-green-500/30 bg-green-500/10 p-4">
        <h4 className="mb-2 flex items-center gap-2 font-semibold text-green-400">
          <Database className="h-5 w-5" />
          No Threats Found
        </h4>
        <p className="text-sm text-slate-300">
          This hash was not found in the configured malicious hash feeds.
        </p>
      </div>
    );
  };

  return (
    <div className="global-scroll flex-1 bg-slate-900">
      <div className="p-4 sm:p-6 xl:p-8">
        <h2 className="mb-2 text-3xl font-bold text-white">Hash Checker</h2>
        <p className="mb-8 text-slate-400">Check file hashes against real reputation sources</p>

        <div className="mx-auto max-w-4xl">
          <form onSubmit={handleScan} className="mb-6 space-y-4">
            <div className="flex flex-col gap-4 lg:flex-row">
              <select
                value={hashType}
                onChange={(e) => setHashType(e.target.value as 'MD5' | 'SHA1' | 'SHA256')}
                className="w-full rounded-lg border border-slate-600 bg-slate-900/50 px-4 py-4 text-white transition focus:outline-none focus:ring-2 focus:ring-cyan-500 lg:w-auto"
                disabled={scanning}
              >
                <option value="MD5">MD5</option>
                <option value="SHA1">SHA-1</option>
                <option value="SHA256">SHA-256</option>
              </select>
              <div className="relative flex-1">
                <Hash className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  value={hash}
                  onChange={(e) => setHash(e.target.value.toLowerCase().trim())}
                  placeholder={`Enter ${hashType} hash`}
                  className="w-full rounded-lg border border-slate-600 bg-slate-900/50 py-4 pl-12 pr-4 font-mono text-sm text-white placeholder-slate-500 transition focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  required
                  disabled={scanning}
                />
              </div>
            </div>
            <button
              type="submit"
              disabled={scanning || !hash}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 px-8 py-4 font-semibold text-white transition hover:from-cyan-600 hover:to-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <Search className="h-5 w-5" /> Check Hash
            </button>
          </form>

          {error && (
            <div className="mb-6 rounded-lg border border-red-500/30 bg-red-500/10 p-4">
              <div className="flex items-center gap-2 text-red-400">
                <AlertCircle className="h-5 w-5" />
                <p className="font-medium">{error}</p>
              </div>
            </div>
          )}

          {scanning && (
            <div className="mb-6 rounded-xl border border-slate-700 bg-slate-800/50 p-8 text-center">
              <Loader2 className="mx-auto mb-4 h-12 w-12 animate-spin text-cyan-400" />
              <h3 className="mb-2 text-xl font-semibold text-white">Checking Hash...</h3>
              <p className="text-slate-400">Querying local history, MalwareBazaar, and external hash lookup feeds</p>
            </div>
          )}

          {result && !scanning && (
            <div className="space-y-6 rounded-xl border border-slate-700 bg-slate-800/50 p-8">
              <div className="text-center">
                <div className="mb-4 flex justify-center">{getStatusIcon()}</div>
                <h3 className="mb-2 text-2xl font-bold text-white">Scan Complete</h3>
                <span className={`inline-block rounded-full border px-4 py-2 text-sm font-semibold ${getStatusColor()}`}>
                  {result.status.toUpperCase()}
                </span>
              </div>

              <div className="space-y-4 rounded-lg border border-slate-700 bg-slate-900/50 p-4 text-sm">
                <div>
                  <p className="text-slate-500">Hash Value</p>
                  <p className="break-all font-mono font-medium text-white">{result.details.hash}</p>
                </div>
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <div>
                    <p className="text-slate-500">Hash Type</p>
                    <p className="font-medium text-white">{result.details.hashType}</p>
                  </div>
                  <div>
                    <p className="text-slate-500">Malicious Match</p>
                    <p className="font-medium text-white">{result.details.found ? 'Yes' : 'No'}</p>
                  </div>
                  <div>
                    <p className="text-slate-500">Detections / Sources</p>
                    <p className="font-medium text-white">
                      {result.details.detections}/{result.details.engines}
                    </p>
                  </div>
                  <div>
                    <p className="text-slate-500">Threat Score</p>
                    <p className="font-medium text-white">{result.threatScore}/100</p>
                  </div>
                </div>
                {result.details.sources && result.details.sources.length > 0 && (
                  <div>
                    <p className="mb-2 text-slate-500">Evidence Sources</p>
                    <div className="flex flex-wrap gap-2">
                      {result.details.sources.map((source) => (
                        <span
                          key={source}
                          className="rounded-full border border-slate-600 bg-slate-800 px-2 py-1 text-xs text-slate-300"
                        >
                          {source}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {result.details.evidence && result.details.evidence.length > 0 && (
                  <div>
                    <p className="mb-2 text-slate-500">Evidence</p>
                    <ul className="space-y-2 text-slate-300">
                      {result.details.evidence.map((item, index) => (
                        <li key={`${item}-${index}`} className="rounded-lg border border-slate-700 bg-slate-800/60 px-3 py-2">
                          {item}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              {renderDetailedResult()}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
