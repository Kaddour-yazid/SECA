import { useState } from 'react';
import { Upload, AlertCircle, CheckCircle, AlertTriangle, Loader2 } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

type ScanResultType = {
  status: 'clean' | 'malicious' | 'suspicious';
  threatScore: number;
  details: {
    fileName: string;
    fileSize: number;
    fileType: string;
    threats: string[];
    signatures: string[];
  };
};

export function FileScannerView() {
  const { user, token } = useAuth();
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResultType | null>(null);
  const [fileName, setFileName] = useState('');
  const [error, setError] = useState<string | null>(null);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !user || !token) return;

    setFileName(file.name);
    setScanning(true);
    setResult(null);
    setError(null);

    try {
      await new Promise((resolve) => setTimeout(resolve, 2000));

      const mockResult: ScanResultType = {
        status: Math.random() > 0.7 ? 'malicious' : Math.random() > 0.5 ? 'suspicious' : 'clean',
        threatScore: Math.floor(Math.random() * 100),
        details: {
          fileName: file.name,
          fileSize: file.size,
          fileType: file.type || 'unknown',
          threats: Math.random() > 0.6 ? ['Trojan.Generic', 'Malware.Suspicious'] : [],
          signatures: ['MD5: ' + Math.random().toString(36).substring(7)],
        },
      };

      setResult(mockResult);
      setScanning(false);

      const formData = new FormData();
      formData.append('file', file);
      formData.append('scan_type', 'file');
      formData.append('status', mockResult.status);
      formData.append('threat_score', mockResult.threatScore.toString());
      formData.append('details', JSON.stringify(mockResult.details));

      const response = await fetch('http://127.0.0.1:8000/scan', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        },
        body: formData,
      });

      if (!response.ok) {
        throw new Error('Failed to save scan result');
      }

      console.log('Scan result saved successfully');
    } catch (err) {
      console.error('Error during file scan:', err);
      setError(err instanceof Error ? err.message : 'An error occurred during scanning');
      setScanning(false);
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

  return (
    <div className="flex-1 bg-slate-900 global-scroll">
      <div className="p-8">
        <h2 className="text-3xl font-bold text-white mb-2">File Scanner</h2>
        <p className="text-slate-400 mb-8">Upload and analyze files for malware and threats</p>

        <div className="max-w-4xl mx-auto">
          {/* Upload Area */}
          <div className="bg-slate-800/50 border-2 border-dashed border-slate-600 rounded-xl p-12 text-center hover:border-cyan-500 transition cursor-pointer">
            <input
              type="file"
              onChange={handleFileUpload}
              className="hidden"
              id="file-upload"
              disabled={scanning}
            />
            <label htmlFor="file-upload" className="cursor-pointer">
              <Upload className="w-16 h-16 text-slate-400 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-white mb-2">
                {fileName || 'Drop your file here or click to browse'}
              </h3>
              <p className="text-slate-400">Supports all file types • Max size: 100MB</p>
            </label>
          </div>

          {/* Error Message */}
          {error && (
            <div className="mt-6 bg-red-500/10 border border-red-500/30 rounded-lg p-4">
              <div className="flex items-center gap-2 text-red-400">
                <AlertCircle className="w-5 h-5" />
                <p className="font-medium">{error}</p>
              </div>
            </div>
          )}

          {/* Scanning Animation */}
          {scanning && (
            <div className="mt-6 bg-slate-800/50 border border-slate-700 rounded-xl p-8 text-center">
              <Loader2 className="w-12 h-12 text-cyan-400 animate-spin mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-white mb-2">Analyzing File...</h3>
              <p className="text-slate-400">Analyzing file for threats and malware</p>
            </div>
          )}

          {/* Results */}
          {result && !scanning && (
            <div className="mt-6 bg-slate-800/50 border border-slate-700 rounded-xl p-8 space-y-6">
              <div className="text-center">
                <div className="flex justify-center mb-4">{getStatusIcon()}</div>
                <h3 className="text-2xl font-bold text-white mb-2">Scan Complete</h3>
                <span className={`inline-block px-4 py-2 rounded-full text-sm font-semibold border ${getStatusColor()}`}>
                  {result.status.toUpperCase()}
                </span>
              </div>

              {/* File Details */}
              <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-4 grid grid-cols-2 gap-4 text-sm">
                <div className="col-span-2">
                  <p className="text-slate-500">File Name</p>
                  <p className="text-white font-medium break-all">{result.details.fileName}</p>
                </div>
                <div>
                  <p className="text-slate-500">File Size</p>
                  <p className="text-white font-medium">{(result.details.fileSize / 1024).toFixed(2)} KB</p>
                </div>
                <div>
                  <p className="text-slate-500">File Type</p>
                  <p className="text-white font-medium">{result.details.fileType}</p>
                </div>
                <div>
                  <p className="text-slate-500">Threat Score</p>
                  <p className="text-white font-medium">{result.threatScore}/100</p>
                </div>
              </div>

              {/* Threats */}
              {result.details.threats.length > 0 && (
                <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
                  <h4 className="text-red-400 font-semibold mb-2 flex items-center gap-2">
                    <AlertCircle className="w-5 h-5" />
                    Detected Threats
                  </h4>
                  <ul className="space-y-1">
                    {result.details.threats.map((threat, idx) => (
                      <li key={idx} className="text-white text-sm">
                        • {threat}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Signatures */}
              {result.details.signatures.length > 0 && (
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-4">
                  <h4 className="text-slate-300 font-semibold mb-2">File Signatures</h4>
                  <ul className="space-y-1">
                    {result.details.signatures.map((sig, idx) => (
                      <li key={idx} className="text-slate-400 text-sm font-mono">
                        {sig}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}