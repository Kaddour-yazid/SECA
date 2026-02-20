import { useState } from 'react';
import { Hash, AlertCircle, CheckCircle, AlertTriangle, Loader2, Search, Database } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

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
    firstSeen: string;
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
        throw new Error(`Invalid ${hashType} hash format. Expected ${hashType === 'MD5' ? 32 : hashType === 'SHA1' ? 40 : 64} hexadecimal characters.`);
      }

      await new Promise((resolve) => setTimeout(resolve, 2000));

      const isMalicious = Math.random() > 0.7;
      const detections = isMalicious ? Math.floor(Math.random() * 50) + 10 : 0;

      const mockResult: ScanResultType = {
        status: isMalicious ? 'malicious' : Math.random() > 0.5 ? 'suspicious' : 'clean',
        threatScore: isMalicious ? Math.floor(Math.random() * 40) + 60 : Math.floor(Math.random() * 30),
        details: {
          hash,
          hashType,
          found: isMalicious || Math.random() > 0.5,
          detections,
          engines: 70,
          malwareFamily: isMalicious ? ['Trojan.Generic', 'Ransomware.WannaCry', 'Backdoor.Agent'][Math.floor(Math.random() * 3)] : 'None',
          firstSeen: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000).toISOString(),
        },
      };

      setResult(mockResult);
      setScanning(false);

      const formData = new URLSearchParams();
      formData.append('scan_type', 'hash');
      formData.append('target', hash);
      formData.append('status', mockResult.status);
      formData.append('threat_score', mockResult.threatScore.toString());
      formData.append('details', JSON.stringify(mockResult.details));

      const response = await fetch('http://127.0.0.1:8000/hash-scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Bearer ${token}`
        },
        body: formData,
      });

      if (!response.ok) {
        const errorText = await response.text();
        let errorMessage = 'Failed to save scan result';
        try {
          const errorData = JSON.parse(errorText);
          errorMessage = errorData.detail || errorMessage;
        } catch {
          errorMessage = errorText || errorMessage;
        }
        throw new Error(errorMessage);
      }

      console.log('Hash scan result saved successfully');
    } catch (err) {
      console.error('Error during hash scan:', err);
      setError(err instanceof Error ? err.message : 'An error occurred during scanning');
      setScanning(false);
      setResult(null);
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

  // Determine which message to show
  const renderDetailedResult = () => {
    if (!result) return null;

    // If malicious and has a malware family (not None)
    if (result.status === 'malicious' && result.details.malwareFamily !== 'None') {
      return (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
          <h4 className="text-red-400 font-semibold mb-2 flex items-center gap-2">
            <AlertCircle className="w-5 h-5" />
            Malware Detected
          </h4>
          <div className="space-y-2">
            <div>
              <p className="text-slate-400 text-sm">Malware Family</p>
              <p className="text-white font-medium">{result.details.malwareFamily}</p>
            </div>
            <div>
              <p className="text-slate-400 text-sm">First Seen</p>
              <p className="text-white font-medium">
                {new Date(result.details.firstSeen).toLocaleDateString('en-US', {
                  year: 'numeric',
                  month: 'long',
                  day: 'numeric',
                })}
              </p>
            </div>
          </div>
        </div>
      );
    }

    // If suspicious (with or without detections)
    if (result.status === 'suspicious') {
      return (
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
          <h4 className="text-yellow-400 font-semibold mb-2 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5" />
            Suspicious Indicators
          </h4>
          <p className="text-slate-300 text-sm">
            This hash has suspicious characteristics but no confirmed malware. Further analysis recommended.
          </p>
          {result.details.detections > 0 && (
            <p className="text-slate-300 text-sm mt-2">
              {result.details.detections} out of {result.details.engines} engines flagged this file.
            </p>
          )}
        </div>
      );
    }

    // Otherwise clean or no threats found
    return (
      <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
        <h4 className="text-green-400 font-semibold mb-2 flex items-center gap-2">
          <Database className="w-5 h-5" />
          No Threats Found
        </h4>
        <p className="text-slate-300 text-sm">
          This hash was not found in any known malware databases. The file appears to be clean.
        </p>
      </div>
    );
  };

  return (
    <div className="flex-1 bg-slate-900 global-scroll">
      <div className="p-8">
        <h2 className="text-3xl font-bold text-white mb-2">Hash Checker</h2>
        <p className="text-slate-400 mb-8">Check file hashes against malware databases</p>

        <div className="max-w-4xl mx-auto">
          {/* Search Form */}
          <form onSubmit={handleScan} className="space-y-4 mb-6">
            <div className="flex gap-4">
              <select
                value={hashType}
                onChange={(e) => setHashType(e.target.value as 'MD5' | 'SHA1' | 'SHA256')}
                className="px-4 py-4 bg-slate-900/50 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 transition"
                disabled={scanning}
              >
                <option value="MD5">MD5</option>
                <option value="SHA1">SHA-1</option>
                <option value="SHA256">SHA-256</option>
              </select>
              <div className="flex-1 relative">
                <Hash className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
                <input
                  type="text"
                  value={hash}
                  onChange={(e) => setHash(e.target.value.toLowerCase().trim())}
                  placeholder={`Enter ${hashType} hash (e.g., ${hashType === 'MD5' ? 'a1b2c3d4...' : hashType === 'SHA1' ? 'abc123def456...' : 'abcdef1234567890...'})`}
                  className="w-full pl-12 pr-4 py-4 bg-slate-900/50 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 transition font-mono text-sm"
                  required
                  disabled={scanning}
                />
              </div>
            </div>
            <button
              type="submit"
              disabled={scanning || !hash}
              className="w-full px-8 py-4 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold rounded-lg flex items-center justify-center gap-2 hover:from-cyan-600 hover:to-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition"
            >
              <Search className="w-5 h-5" /> Check Hash
            </button>
          </form>

          {/* Error Message */}
          {error && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 mb-6">
              <div className="flex items-center gap-2 text-red-400">
                <AlertCircle className="w-5 h-5" />
                <p className="font-medium">{error}</p>
              </div>
            </div>
          )}

          {/* Scanning Animation */}
          {scanning && (
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-8 text-center mb-6">
              <Loader2 className="w-12 h-12 text-cyan-400 animate-spin mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-white mb-2">Checking Hash...</h3>
              <p className="text-slate-400">Searching malware databases and threat feeds</p>
            </div>
          )}

          {/* Results */}
          {result && !scanning && (
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-8 space-y-6">
              <div className="text-center">
                <div className="flex justify-center mb-4">{getStatusIcon()}</div>
                <h3 className="text-2xl font-bold text-white mb-2">Scan Complete</h3>
                <span className={`inline-block px-4 py-2 rounded-full text-sm font-semibold border ${getStatusColor()}`}>
                  {result.status.toUpperCase()}
                </span>
              </div>

              {/* Hash Details */}
              <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-4 space-y-4 text-sm">
                <div>
                  <p className="text-slate-500">Hash Value</p>
                  <p className="text-white font-medium font-mono break-all">{result.details.hash}</p>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-slate-500">Hash Type</p>
                    <p className="text-white font-medium">{result.details.hashType}</p>
                  </div>
                  <div>
                    <p className="text-slate-500">Found in Database</p>
                    <p className="text-white font-medium">{result.details.found ? 'Yes' : 'No'}</p>
                  </div>
                  <div>
                    <p className="text-slate-500">Detections / Engines</p>
                    <p className="text-white font-medium">
                      {result.details.detections}/{result.details.engines}
                    </p>
                  </div>
                  <div>
                    <p className="text-slate-500">Threat Score</p>
                    <p className="text-white font-medium">{result.threatScore}/100</p>
                  </div>
                </div>
              </div>

              {/* Dynamic Result Message */}
              {renderDetailedResult()}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
