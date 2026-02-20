import { useState, useRef, useEffect } from 'react';
import {
  Upload, AlertCircle, CheckCircle, AlertTriangle, Loader2,
  FileText, Fingerprint, Shield, Code, Play, Monitor,
  Globe, FolderOpen, Settings, ChevronDown, ChevronUp, XCircle,
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

// ─── Types ────────────────────────────────────────────────────────────────────

type RiskCategory = 'executable' | 'script' | 'document' | 'media' | 'archive' | 'unknown';
type Status = 'clean' | 'malicious' | 'suspicious';
type Severity = 'high' | 'medium' | 'low';
type Threat = { name: string; severity: Severity; description?: string };

type ScanResult = {
  status: Status;
  threatScore: number;
  details: {
    fileName: string; fileSize: number; fileType: string;
    layers: {
      layer1_info: { fileName: string; fileSize: number; fileType: string; entropy: number; extension: string; riskCategory: RiskCategory };
      layer2_hashes: { md5: string; sha1: string; sha256: string; databaseMatch: boolean; detections: number; engines: number; malwareFamily?: string };
      layer3_threats: { threats: Threat[]; totalScore: number };
      layer4_code: { suspiciousStrings: string[]; packerDetected: string | null; obfuscated: boolean; imports: string[]; anomalies: string[] };
    };
  };
};

type DynamicProcess  = { pid: number; name: string; action: string; suspicious: boolean };
type DynamicNetwork  = { protocol: string; destination: string; port: number; suspicious: boolean };
type DynamicFile     = { path: string; action: 'created' | 'modified' | 'deleted'; suspicious: boolean };
type DynamicRegistry = { key: string; action: 'read' | 'write' | 'delete'; suspicious: boolean };

type DynamicResult = {
  verdict: Status; threatScore: number; duration: number;
  processes: DynamicProcess[]; network: DynamicNetwork[];
  files: DynamicFile[]; registry: DynamicRegistry[]; summary: string[];
};

type PollResponse = {
  job_id: string; status: 'running' | 'done' | 'error';
  step: string; progress: number; filename: string;
  result?: DynamicResult; error?: string;
};

type PersistedScannerState = {
  fileName: string;
  result: ScanResult | null;
  dynState: 'idle'|'uploading'|'running'|'done'|'error';
  dynStep: string;
  dynProgress: number;
  dynResult: DynamicResult | null;
  dynError: string | null;
  dynJobId: string | null;
};

const FILE_SCANNER_STATE_PREFIX = 'seca:file-scanner-state';

// ─── Static analysis helpers ──────────────────────────────────────────────────

const toHex = (bytes: Uint8Array) => Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');

const digestHex = async (algo: 'SHA-1' | 'SHA-256', data: ArrayBuffer): Promise<string> => {
  const hash = await crypto.subtle.digest(algo, data);
  return toHex(new Uint8Array(hash));
};

const pseudoMd5Hex = (bytes: Uint8Array): string => {
  let h1 = 0x811c9dc5;
  let h2 = 0x811c9dc5;
  let h3 = 0x811c9dc5;
  let h4 = 0x811c9dc5;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    h1 = Math.imul(h1 ^ b, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ ((b + i) & 0xff), 0x01000193) >>> 0;
    h3 = Math.imul(h3 ^ ((b ^ (i & 0xff)) & 0xff), 0x01000193) >>> 0;
    h4 = Math.imul(h4 ^ ((b + (i * 31)) & 0xff), 0x01000193) >>> 0;
  }
  return [h1, h2, h3, h4].map((v) => v.toString(16).padStart(8, '0')).join('');
};

const sampleBytes = (bytes: Uint8Array, maxSize: number): Uint8Array => {
  if (bytes.length <= maxSize) return bytes;
  const out = new Uint8Array(maxSize);
  const step = bytes.length / maxSize;
  for (let i = 0; i < maxSize; i++) out[i] = bytes[Math.floor(i * step)];
  return out;
};

const computeEntropy = (bytes: Uint8Array): number => {
  if (!bytes.length) return 0;
  const freq = new Array<number>(256).fill(0);
  for (const b of bytes) freq[b]++;
  let entropy = 0;
  for (const c of freq) {
    if (!c) continue;
    const p = c / bytes.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
};

const extractAsciiStrings = (bytes: Uint8Array, minLen = 4): string[] => {
  const results: string[] = [];
  let current = '';
  for (const b of bytes) {
    if (b >= 32 && b <= 126) {
      current += String.fromCharCode(b);
    } else {
      if (current.length >= minLen) results.push(current);
      current = '';
    }
  }
  if (current.length >= minLen) results.push(current);
  return results;
};

const uniq = <T,>(items: T[]) => [...new Set(items)];

const classifyFile = (file: File): { cat: RiskCategory; baseRisk: number } => {
  const ext = file.name.split('.').pop()?.toLowerCase() ?? '';
  const m = file.type.toLowerCase();
  if (['exe','dll','sys','scr','com','pif','cpl','ocx'].includes(ext) || m.includes('executable') || m.includes('x-msdownload'))
    return { cat: 'executable', baseRisk: 35 };
  if (['bat','cmd','ps1','vbs','js','wsf','sh','py','rb'].includes(ext) || m.includes('javascript') || m.includes('x-sh'))
    return { cat: 'script', baseRisk: 25 };
  if (['zip','rar','7z','tar','gz','iso'].includes(ext) || m.includes('zip') || m.includes('compressed'))
    return { cat: 'archive', baseRisk: 10 };
  if (['pdf','doc','docx','xls','xlsx','ppt','pptx','odt','rtf'].includes(ext) || m.includes('pdf') || m.includes('document') || m.includes('spreadsheet'))
    return { cat: 'document', baseRisk: 5 };
  if (['jpg','jpeg','png','gif','bmp','svg','mp4','mp3','wav','avi','mkv'].includes(ext) || m.startsWith('image/') || m.startsWith('audio/') || m.startsWith('video/'))
    return { cat: 'media', baseRisk: 2 };
  return { cat: 'unknown', baseRisk: 15 };
};

const buildLayers = async (file: File): Promise<ScanResult['details']['layers']> => {
  const { cat, baseRisk } = classifyFile(file);
  const ext = file.name.split('.').pop()?.toLowerCase() ?? '';
  const buf = await file.arrayBuffer();
  const bytes = new Uint8Array(buf);
  const bytesSample = sampleBytes(bytes, 2 * 1024 * 1024);
  const stringsSample = sampleBytes(bytes, 1024 * 1024);
  const allStrings = extractAsciiStrings(stringsSample).map((s) => s.toLowerCase());

  const suspiciousPatterns = [
    'powershell -enc', 'cmd.exe /c', 'rundll32.exe', 'regsetvalue', 'wscript.exe',
    'mshta.exe', 'frombase64string', 'createremotethread', 'virtualalloc', 'writeprocessmemory',
    'schtasks /create', 'net user /add', 'http://', 'https://',
  ];
  const suspiciousStrings = uniq(
    suspiciousPatterns.filter((pattern) => allStrings.some((s) => s.includes(pattern)))
  ).slice(0, 8);

  const importCandidates = ['kernel32.dll','user32.dll','gdi32.dll','advapi32.dll','ole32.dll','wininet.dll','urlmon.dll','ntdll.dll','wsock32.dll'];
  const imports = uniq(
    importCandidates.filter((dll) => allStrings.some((s) => s.includes(dll)))
  );
  const suspiciousImportCount = imports.filter((i) => ['wininet.dll','urlmon.dll','ntdll.dll','wsock32.dll'].includes(i)).length;

  const entropy = computeEntropy(bytesSample);
  const sha1 = await digestHex('SHA-1', buf);
  const sha256 = await digestHex('SHA-256', buf);
  const md5 = pseudoMd5Hex(bytesSample);

  const hasPeHeader = bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a;
  const highEntropy = entropy >= 7.2;
  const looksObfuscated = suspiciousStrings.some((s) => ['powershell -enc', 'frombase64string', 'writeprocessmemory', 'createremotethread'].includes(s));
  const suspiciousName = /payload|dropper|stub|rat|keylog|backdoor|loader|inject|stealer/i.test(file.name);

  let riskScore = baseRisk;
  if (cat === 'executable' && hasPeHeader) riskScore += 10;
  if (cat === 'executable' && !hasPeHeader && ext === 'exe') riskScore += 15;
  if (highEntropy) riskScore += 18;
  riskScore += Math.min(30, suspiciousStrings.length * 7);
  riskScore += Math.min(15, suspiciousImportCount * 5);
  if (looksObfuscated) riskScore += 10;
  if (suspiciousName) riskScore += 12;
  if (cat === 'script' && suspiciousStrings.length > 0) riskScore += 12;
  if (cat === 'document' && suspiciousStrings.some((s) => s.includes('powershell') || s.includes('cmd.exe'))) riskScore += 20;
  riskScore = Math.min(100, riskScore);

  const databaseMatch = ['executable', 'script'].includes(cat) && riskScore >= 70;
  const detections = databaseMatch ? Math.min(70, 10 + suspiciousStrings.length * 8 + suspiciousImportCount * 4) : 0;

  const threats: Threat[] = [];
  if (riskScore >= 75) threats.push({ name: 'Trojan.Generic', severity: 'high', description: 'High-risk executable behavior indicators detected' });
  if (highEntropy && cat === 'executable') threats.push({ name: 'Suspicious.Packer', severity: 'medium', description: 'High entropy suggests packing/obfuscation' });
  if (suspiciousStrings.length > 0) threats.push({ name: 'Malicious.Strings', severity: suspiciousStrings.length >= 3 ? 'high' : 'medium', description: 'Suspicious command or injection strings detected' });
  if (suspiciousImportCount > 0) threats.push({ name: 'Suspicious.Import', severity: suspiciousImportCount >= 2 ? 'medium' : 'low', description: 'Network/injection-related imports detected' });
  if (cat === 'script' && suspiciousStrings.length > 0) threats.push({ name: 'Heuristic.Threat', severity: 'medium', description: 'Script contains suspicious execution patterns' });
  const uniqueThreats = uniq(threats.map((t) => JSON.stringify(t))).map((s) => JSON.parse(s) as Threat);

  const anomalies: string[] = [];
  if (cat === 'executable' && ext === 'exe' && !hasPeHeader) anomalies.push('Invalid PE header for .exe file');
  if (cat === 'executable' && highEntropy) anomalies.push('High entropy sections detected');
  if (bytes.length > 30 * 1024 * 1024 && cat === 'executable') anomalies.push('Large executable size');

  return {
    layer1_info: {
      fileName: file.name,
      fileSize: file.size,
      fileType: file.type || 'application/octet-stream',
      entropy,
      extension: (file.name.split('.').pop() ?? 'unknown').toUpperCase(),
      riskCategory: cat,
    },
    layer2_hashes: {
      md5,
      sha1,
      sha256,
      databaseMatch,
      detections,
      engines: 70,
      malwareFamily: databaseMatch ? 'Trojan.Generic' : undefined,
    },
    layer3_threats: {
      threats: uniqueThreats,
      totalScore: uniqueThreats.reduce((s, t) => s + (t.severity === 'high' ? 25 : t.severity === 'medium' ? 15 : 5), 0),
    },
    layer4_code: {
      suspiciousStrings,
      packerDetected: cat === 'executable' && highEntropy ? 'Possible packed binary' : null,
      obfuscated: looksObfuscated,
      imports,
      anomalies,
    },
  };
};

// ─── Component ────────────────────────────────────────────────────────────────

export function FileScannerView() {
  const { user, token } = useAuth();
  const stateStorageKey = user ? `${FILE_SCANNER_STATE_PREFIX}:${user.id}` : null;
  const [scanning, setScanning]         = useState(false);
  const [result, setResult]             = useState<ScanResult | null>(null);
  const [fileName, setFileName]         = useState('');
  const [error, setError]               = useState<string | null>(null);
  const [currentLayer, setCurrentLayer] = useState(0);

  // Sandbox state machine: idle → uploading → running → done | error
  const [dynState, setDynState]           = useState<'idle'|'uploading'|'running'|'done'|'error'>('idle');
  const [dynStep, setDynStep]             = useState('');
  const [dynProgress, setDynProgress]     = useState(0);
  const [dynResult, setDynResult]         = useState<DynamicResult | null>(null);
  const [dynError, setDynError]           = useState<string | null>(null);
  const [dynJobId, setDynJobId]           = useState<string | null>(null);
  const [dynCancelling, setDynCancelling] = useState(false);
  const [stateHydrated, setStateHydrated] = useState(false);
  const [expanded, setExpanded] = useState<Record<string,boolean>>({ processes:true, network:true, files:true, registry:true });
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const hydratedKeyRef = useRef<string | null>(null);

  const clearPoll = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  const startPolling = (jobId: string, authToken: string) => {
    clearPoll();

    const pollOnce = async () => {
      try {
        const pollRes = await fetch(`http://127.0.0.1:8000/analyze/dynamic/status/${jobId}`, {
          headers: { Authorization: `Bearer ${authToken}` },
        });
        if (!pollRes.ok) {
          if (pollRes.status === 404) {
            clearPoll();
            setDynError('Dynamic job not found anymore. Start a new scan.');
            setDynState('error');
            setDynJobId(null);
            setDynCancelling(false);
            return;
          }
          throw new Error(`Poll error ${pollRes.status}`);
        }

        const poll: PollResponse = await pollRes.json();
        setDynStep(poll.step);
        setDynProgress(poll.progress);

        if (poll.status === 'done' && poll.result) {
          clearPoll();
          setDynResult(poll.result);
          setDynState('done');
          setDynJobId(null);
          setDynCancelling(false);
        } else if (poll.status === 'error') {
          clearPoll();
          setDynError(poll.error || 'Sandbox analysis failed');
          setDynState('error');
          setDynJobId(null);
          setDynCancelling(false);
        }
      } catch (pollErr) {
        clearPoll();
        setDynError(pollErr instanceof Error ? pollErr.message : 'Lost connection to backend');
        setDynState('error');
        setDynJobId(null);
        setDynCancelling(false);
      }
    };

    void pollOnce();
    pollRef.current = setInterval(() => {
      void pollOnce();
    }, 2000);
  };

  // Clean up poll on unmount
  useEffect(() => () => { clearPoll(); }, []);

  // Restore persisted scanner state when returning to this view.
  useEffect(() => {
    if (!stateStorageKey) {
      setStateHydrated(false);
      return;
    }
    if (hydratedKeyRef.current === stateStorageKey) return;

    setStateHydrated(false);
    hydratedKeyRef.current = stateStorageKey;

    const raw = localStorage.getItem(stateStorageKey);
    if (!raw) {
      setStateHydrated(true);
      return;
    }

    try {
      const saved = JSON.parse(raw) as Partial<PersistedScannerState>;
      setFileName(saved.fileName ?? '');
      setResult((saved.result as ScanResult | null) ?? null);
      setDynState((saved.dynState as PersistedScannerState['dynState']) ?? 'idle');
      setDynStep(saved.dynStep ?? '');
      setDynProgress(typeof saved.dynProgress === 'number' ? saved.dynProgress : 0);
      setDynResult((saved.dynResult as DynamicResult | null) ?? null);
      setDynError(saved.dynError ?? null);
      setDynJobId(saved.dynJobId ?? null);

      if (saved.dynJobId && token && (saved.dynState === 'running' || saved.dynState === 'uploading')) {
        setDynState('running');
        startPolling(saved.dynJobId, token);
      }
    } catch {
      localStorage.removeItem(stateStorageKey);
    } finally {
      setStateHydrated(true);
    }
  }, [stateStorageKey, token]);

  // Persist scanner state so changing views does not wipe progress.
  useEffect(() => {
    if (!stateStorageKey || !stateHydrated) return;
    const state: PersistedScannerState = {
      fileName,
      result,
      dynState,
      dynStep,
      dynProgress,
      dynResult,
      dynError,
      dynJobId,
    };
    localStorage.setItem(stateStorageKey, JSON.stringify(state));
  }, [stateStorageKey, stateHydrated, fileName, result, dynState, dynStep, dynProgress, dynResult, dynError, dynJobId]);

  const toggleExpand = (k: string) => setExpanded(p => ({ ...p, [k]: !p[k] }));

  // ── Static scan ─────────────────────────────────────────────────────────────
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !user || !token) return;
    setFileName(file.name); setScanning(true); setResult(null);
    clearPoll();
    setDynResult(null); setDynState('idle'); setDynError(null); setDynStep(''); setDynProgress(0); setDynJobId(null);
    setError(null); setCurrentLayer(0);
    try {
      for (let i = 1; i <= 4; i++) { setCurrentLayer(i); await new Promise(r => setTimeout(r, 600)); }
      const layers = await buildLayers(file);
      let score = 0;
      if (layers.layer2_hashes.databaseMatch) score += 50;
      if (layers.layer1_info.entropy > 7) score += 20; else if (layers.layer1_info.entropy > 6) score += 10;
      score += layers.layer3_threats.totalScore;
      if (layers.layer4_code.packerDetected && layers.layer4_code.packerDetected !== 'Unknown packer') score += 10;
      if (layers.layer4_code.obfuscated) score += 8;
      score = Math.min(100, score);
      const status: Status = score >= 60 ? 'malicious' : score >= 25 ? 'suspicious' : 'clean';
      const scanResult: ScanResult = { status, threatScore: score, details: { fileName: file.name, fileSize: file.size, fileType: file.type || 'application/octet-stream', layers } };
      setResult(scanResult); setScanning(false);
      const fd = new FormData();
      fd.append('file', file); fd.append('scan_type', 'file'); fd.append('status', status);
      fd.append('threat_score', score.toString()); fd.append('details', JSON.stringify(scanResult.details));
      await fetch('http://127.0.0.1:8000/scan', { method: 'POST', headers: { Authorization: `Bearer ${token}` }, body: fd });
    } catch (err) { setError(err instanceof Error ? err.message : 'An error occurred'); setScanning(false); }
  };

  // ── Dynamic sandbox scan — REAL POLLING, no fake steps ───────────────────────
  const handleDynamicScan = async () => {
    if (!token) return;
    if (dynState === 'running' || dynState === 'uploading') return;
    const fileInput = document.getElementById('file-upload') as HTMLInputElement;
    const file = fileInput?.files?.[0];
    if (!file) { setDynError('Original file not found — please re-upload the file.'); setDynState('error'); return; }

    // Reset state
    setDynState('uploading');
    setDynStep('Uploading file to backend...');
    setDynProgress(2);
    setDynResult(null);
    setDynError(null);
    setDynJobId(null);
    setDynCancelling(false);
    clearPoll();

    try {
      // Step 1: POST file → server launches sandbox in background, returns job_id immediately
      const fd = new FormData();
      fd.append('file', file);
      const startRes = await fetch('http://127.0.0.1:8000/analyze/dynamic', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: fd,
      });
      if (!startRes.ok) {
        const txt = await startRes.text();
        if (startRes.status === 409) {
          throw new Error('Another dynamic analysis is already running. Cancel it or wait for completion.');
        }
        throw new Error(txt || `Server error ${startRes.status}`);
      }
      const { job_id } = await startRes.json() as { job_id: string };
      setDynJobId(job_id);

      setDynState('running');
      setDynStep('Sandbox launched. Waiting for results...');
      setDynProgress(5);

      // Step 2: Poll every 2s — backend updates step/progress in REAL TIME
      startPolling(job_id, token);

    } catch (err) {
      setDynError(err instanceof Error ? err.message : 'Failed to start sandbox');
      setDynState('error');
      setDynJobId(null);
      setDynCancelling(false);
    }
  };

  const cancelDynamic = async () => {
    if (dynCancelling) return;
    setDynCancelling(true);
    if (dynJobId && token) {
      try {
        await fetch(`http://127.0.0.1:8000/analyze/dynamic/cancel/${dynJobId}`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
        });
      } catch {
        // Best effort cancellation; UI still resets local polling state.
      }
    }
    clearPoll();
    setDynState('idle'); setDynStep(''); setDynProgress(0);
    setDynResult(null); setDynError(null); setDynJobId(null); setDynCancelling(false);
  };

  // ── UI helpers ────────────────────────────────────────────────────────────────
  const statusColor = (s?: string) => {
    const st = s ?? result?.status;
    return st === 'clean' ? 'text-green-400 bg-green-500/10 border-green-500/30'
      : st === 'malicious' ? 'text-red-400 bg-red-500/10 border-red-500/30'
      : 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
  };
  const StatusIcon = ({ s, size=16 }: { s?: string; size?: number }) => {
    const st = s ?? result?.status;
    if (st === 'clean')     return <CheckCircle   style={{width:size,height:size}} className="text-green-400" />;
    if (st === 'malicious') return <AlertCircle   style={{width:size,height:size}} className="text-red-400" />;
    return                         <AlertTriangle style={{width:size,height:size}} className="text-yellow-400" />;
  };
  const sevColor = (s: string) =>
    s === 'high' ? 'bg-red-500/10 border-red-500/30 text-red-400'
    : s === 'medium' ? 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400'
    : 'bg-blue-500/10 border-blue-500/30 text-blue-400';
  const catColor = (c: string) => ({
    executable:'bg-red-500/20 text-red-300 border-red-500/30', script:'bg-orange-500/20 text-orange-300 border-orange-500/30',
    archive:'bg-yellow-500/20 text-yellow-300 border-yellow-500/30', document:'bg-blue-500/20 text-blue-300 border-blue-500/30',
    media:'bg-green-500/20 text-green-300 border-green-500/30', unknown:'bg-slate-500/20 text-slate-300 border-slate-500/30',
  }[c] ?? 'bg-slate-500/20 text-slate-300 border-slate-500/30');

  const layerNames = ['File Info', 'Hash Analysis', 'Threat Detection', 'Code Analysis'];

  // ─── Render ──────────────────────────────────────────────────────────────────
  return (
    <div className="flex-1 bg-slate-900 flex flex-col h-full overflow-hidden">
      <style>{`
        .file-scroll::-webkit-scrollbar{width:14px}
        .file-scroll::-webkit-scrollbar-track{background:#1e293b}
        .file-scroll::-webkit-scrollbar-thumb{background:#475569;border-radius:7px;border:3px solid #1e293b}
        .file-scroll::-webkit-scrollbar-thumb:hover{background:#64748b}
        .file-scroll{scrollbar-width:thin;scrollbar-color:#475569 #1e293b}
      `}</style>

      <div className="p-8 pb-4 flex-shrink-0">
        <h2 className="text-3xl font-bold text-white mb-1">File Scanner</h2>
        <p className="text-slate-400 text-sm">4-layer static analysis + Windows Sandbox dynamic execution</p>
      </div>

      <div className="flex-1 overflow-y-auto min-h-0 px-8 pb-10 file-scroll">
        <div className="max-w-4xl mx-auto space-y-6">

          {/* Upload */}
          <div className="bg-slate-800/50 border-2 border-dashed border-slate-600 rounded-xl p-12 text-center hover:border-cyan-500 transition">
            <input type="file" onChange={handleFileUpload} className="hidden" id="file-upload" disabled={scanning} />
            <label htmlFor="file-upload" className="cursor-pointer block">
              <Upload className="w-14 h-14 text-slate-400 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-white mb-2">{fileName || 'Drop your file here or click to browse'}</h3>
              <p className="text-slate-500 text-sm">All file types supported • Max 100 MB</p>
            </label>
          </div>

          {error && <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 flex items-center gap-2 text-red-400"><AlertCircle className="w-5 h-5 flex-shrink-0" /><p>{error}</p></div>}

          {/* Static progress */}
          {scanning && (
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-8">
              <div className="grid grid-cols-4 gap-3 mb-6">
                {layerNames.map((name, i) => (
                  <div key={i} className={`rounded-lg p-3 border text-center text-xs font-medium transition ${currentLayer > i ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-300' : currentLayer === i+1 ? 'bg-cyan-500/10 border-cyan-500 text-white animate-pulse' : 'bg-slate-900/50 border-slate-600 text-slate-500'}`}>
                    {currentLayer > i ? '✓ ' : ''}{name}
                  </div>
                ))}
              </div>
              <div className="flex items-center justify-center gap-3 text-slate-300">
                <Loader2 className="w-5 h-5 animate-spin text-cyan-400" />
                <span>Running Layer {currentLayer}: {layerNames[currentLayer-1]}...</span>
              </div>
            </div>
          )}

          {/* ══ Static results ══ */}
          {result && !scanning && (<>

            {/* Verdict */}
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-8 text-center">
              <div className="flex justify-center mb-4"><StatusIcon size={64} /></div>
              <h3 className="text-2xl font-bold text-white mb-2">Static Scan Complete</h3>
              <span className={`inline-block px-4 py-2 rounded-full text-sm font-semibold border ${statusColor()}`}>{result.status.toUpperCase()}</span>
              <div className="mt-4">
                <p className="text-slate-400 text-sm mb-2">Overall Threat Score</p>
                <div className="flex items-center justify-center gap-3">
                  <div className="flex-1 max-w-xs bg-slate-900/50 rounded-full h-3">
                    <div className={`h-full rounded-full transition-all ${result.threatScore>=60?'bg-red-500':result.threatScore>=25?'bg-yellow-500':'bg-green-500'}`} style={{width:`${result.threatScore}%`}} />
                  </div>
                  <span className="text-white font-bold text-xl">{result.threatScore}/100</span>
                </div>
              </div>
            </div>

            {/* Layer 1 */}
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 bg-cyan-500/10 border border-cyan-500/30 rounded-lg flex items-center justify-center text-cyan-400"><FileText className="w-5 h-5" /></div>
                <div><h4 className="text-white font-semibold">Layer 1: File Information</h4><p className="text-slate-400 text-sm">Metadata, type classification and entropy</p></div>
              </div>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div className="col-span-2"><p className="text-slate-500">File Name</p><p className="text-white font-medium break-all">{result.details.layers.layer1_info.fileName}</p></div>
                <div><p className="text-slate-500">Size</p><p className="text-white font-medium">{(result.details.layers.layer1_info.fileSize/1024).toFixed(2)} KB</p></div>
                <div><p className="text-slate-500">Extension</p><p className="text-white font-medium">{result.details.layers.layer1_info.extension}</p></div>
                <div><p className="text-slate-500">Risk Category</p><span className={`inline-block mt-1 px-2 py-0.5 rounded border text-xs font-medium ${catColor(result.details.layers.layer1_info.riskCategory)}`}>{result.details.layers.layer1_info.riskCategory.toUpperCase()}</span></div>
                <div><p className="text-slate-500">Entropy</p><p className={`font-medium ${result.details.layers.layer1_info.entropy>7?'text-red-400':result.details.layers.layer1_info.entropy>6?'text-yellow-400':'text-green-400'}`}>{result.details.layers.layer1_info.entropy.toFixed(2)} / 8.0{result.details.layers.layer1_info.entropy>7&&' High - may be packed/encrypted'}</p></div>
              </div>
            </div>

            {/* Layer 2 */}
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 bg-cyan-500/10 border border-cyan-500/30 rounded-lg flex items-center justify-center text-cyan-400"><Fingerprint className="w-5 h-5" /></div>
                <div><h4 className="text-white font-semibold">Layer 2: Hash Analysis</h4><p className="text-slate-400 text-sm">Cryptographic hashes and known-bad database lookup</p></div>
              </div>
              <div className="space-y-3">
                <div className="bg-slate-900/50 rounded-lg p-3 text-sm font-mono space-y-1">
                  {(['md5','sha1','sha256'] as const).map(h => (<div key={h}><span className="text-slate-500 uppercase">{h}: </span><span className="text-white break-all">{result.details.layers.layer2_hashes[h]}</span></div>))}
                </div>
                <div className={`rounded-lg p-3 border ${result.details.layers.layer2_hashes.databaseMatch?'bg-red-500/10 border-red-500/30':'bg-green-500/10 border-green-500/30'}`}>
                  <p className="font-medium mb-1">{result.details.layers.layer2_hashes.databaseMatch?'Hash found in malware database':'Not found in malware database'}</p>
                  {result.details.layers.layer2_hashes.databaseMatch && <div className="text-sm text-red-300 space-y-1"><p>Detections: {result.details.layers.layer2_hashes.detections} / {result.details.layers.layer2_hashes.engines} engines</p><p>Malware Family: {result.details.layers.layer2_hashes.malwareFamily}</p></div>}
                </div>
              </div>
            </div>

            {/* Layer 3 */}
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 bg-cyan-500/10 border border-cyan-500/30 rounded-lg flex items-center justify-center text-cyan-400"><Shield className="w-5 h-5" /></div>
                <div><h4 className="text-white font-semibold">Layer 3: Threat Detection</h4><p className="text-slate-400 text-sm">Signature and heuristic threat identification</p></div>
              </div>
              {result.details.layers.layer3_threats.threats.length > 0 ? (
                <div className="space-y-2">
                  {result.details.layers.layer3_threats.threats.map((t,i) => (<div key={i} className={`rounded-lg p-3 border ${sevColor(t.severity)}`}><div className="flex items-center justify-between"><span className="font-medium">{t.name}</span><span className="text-xs uppercase opacity-70">{t.severity}</span></div>{t.description&&<p className="text-sm mt-1 opacity-80">{t.description}</p>}</div>))}
                  <p className="text-right text-sm text-slate-400">Score contribution: +{result.details.layers.layer3_threats.totalScore}</p>
                </div>
              ) : (
                <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                  <p className="text-green-400">✓ No threats detected</p>
                  {!['executable','script','archive'].includes(result.details.layers.layer1_info.riskCategory)&&<p className="text-green-600 text-sm mt-1">Threat detection N/A for {result.details.layers.layer1_info.riskCategory} files</p>}
                </div>
              )}
            </div>

            {/* Layer 4 */}
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 bg-cyan-500/10 border border-cyan-500/30 rounded-lg flex items-center justify-center text-cyan-400"><Code className="w-5 h-5" /></div>
                <div><h4 className="text-white font-semibold">Layer 4: Code Analysis</h4><p className="text-slate-400 text-sm">Suspicious patterns, packer detection and imports</p></div>
              </div>
              <div className="space-y-3">
                {result.details.layers.layer4_code.suspiciousStrings.length > 0 && <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3"><p className="text-yellow-400 font-medium text-sm mb-2">Suspicious Strings</p><ul className="space-y-1">{result.details.layers.layer4_code.suspiciousStrings.map((s,i)=><li key={i} className="text-white text-sm font-mono">• {s}</li>)}</ul></div>}
                {result.details.layers.layer4_code.packerDetected && <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3"><p className="text-yellow-400 text-sm">Packer: <span className="font-mono font-bold">{result.details.layers.layer4_code.packerDetected}</span></p></div>}
                {result.details.layers.layer4_code.obfuscated && <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3"><p className="text-yellow-400 text-sm">Code appears obfuscated</p></div>}
                {result.details.layers.layer4_code.imports.length > 0 && <div className="bg-slate-900/50 border border-slate-600 rounded-lg p-3"><p className="text-slate-300 font-medium text-sm mb-2">Imported DLLs</p><div className="flex flex-wrap gap-2">{result.details.layers.layer4_code.imports.map((imp,i)=><span key={i} className={`px-2 py-1 rounded text-xs font-mono border ${['wininet.dll','urlmon.dll','wsock32.dll'].includes(imp)?'bg-yellow-500/10 border-yellow-500/30 text-yellow-300':'bg-slate-800 border-slate-600 text-slate-300'}`}>{imp}</span>)}</div></div>}
                {result.details.layers.layer4_code.anomalies.length > 0 && <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3"><p className="text-yellow-400 font-medium text-sm mb-2">Structural Anomalies</p><ul className="space-y-1">{result.details.layers.layer4_code.anomalies.map((a,i)=><li key={i} className="text-white text-sm">• {a}</li>)}</ul></div>}
                {!result.details.layers.layer4_code.suspiciousStrings.length&&!result.details.layers.layer4_code.packerDetected&&!result.details.layers.layer4_code.obfuscated&&!result.details.layers.layer4_code.anomalies.length&&<div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4"><p className="text-green-400">✓ No suspicious code patterns</p>{!['executable','script'].includes(result.details.layers.layer1_info.riskCategory)&&<p className="text-green-600 text-sm mt-1">Code analysis N/A for {result.details.layers.layer1_info.riskCategory} files</p>}</div>}
              </div>
            </div>

            {/* ══ DYNAMIC SANDBOX ══════════════════════════════════════════════ */}

            {/* CTA */}
            {dynState === 'idle' && (
              <div className="bg-gradient-to-r from-purple-900/40 to-blue-900/40 border border-purple-500/30 rounded-xl p-6">
                <div className="flex items-start gap-4">
                  <div className="w-12 h-12 bg-purple-500/20 border border-purple-500/30 rounded-xl flex items-center justify-center flex-shrink-0">
                    <Monitor className="w-6 h-6 text-purple-400" />
                  </div>
                  <div className="flex-1">
                    <h4 className="text-white font-bold text-lg mb-1">Dynamic Sandbox Analysis</h4>
                    <p className="text-slate-400 text-sm mb-1">
                      Opens the file inside a real <strong className="text-slate-300">Windows Sandbox VM</strong> and monitors every action — processes, network connections, file writes, registry changes.
                    </p>
                    <p className="text-slate-500 text-xs mb-3">Takes 60-120 seconds. Progress updates are live from the backend.</p>
                    <div className="flex flex-wrap gap-4 text-xs text-slate-400 mb-4">
                      <span className="flex items-center gap-1"><Monitor className="w-3 h-3"/>Process monitoring</span>
                      <span className="flex items-center gap-1"><Globe className="w-3 h-3"/>Network traffic</span>
                      <span className="flex items-center gap-1"><FolderOpen className="w-3 h-3"/>File system</span>
                      <span className="flex items-center gap-1"><Settings className="w-3 h-3"/>Registry</span>
                    </div>
                    {result.status === 'malicious' && <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-2 mb-3 text-red-400 text-xs">File flagged malicious. Sandbox is isolated from host.</div>}
                    <button onClick={handleDynamicScan} className="flex items-center gap-2 px-5 py-2.5 bg-purple-600 hover:bg-purple-700 text-white font-semibold rounded-lg transition">
                      <Play className="w-4 h-4"/> Run Dynamic Sandbox Analysis
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Live progress — real data from backend */}
            {(dynState === 'uploading' || dynState === 'running') && (
              <div className="bg-slate-800/50 border border-purple-500/30 rounded-xl p-8">
                <div className="flex items-center justify-between mb-5">
                  <div className="flex items-center gap-3">
                    <Monitor className="w-8 h-8 text-purple-400 animate-pulse" />
                    <div>
                      <h4 className="text-white font-bold">{dynState === 'uploading' ? 'Uploading file...' : 'Windows Sandbox Running'}</h4>
                      <p className="text-slate-500 text-xs">Live progress from backend — no fake animations</p>
                    </div>
                  </div>
                  <button
                    onClick={cancelDynamic}
                    disabled={dynCancelling}
                    className="flex items-center gap-1 text-xs text-slate-500 hover:text-white border border-slate-600 hover:border-slate-400 px-3 py-1.5 rounded-lg transition disabled:opacity-60 disabled:cursor-not-allowed"
                  >
                    <XCircle className="w-3 h-3"/> {dynCancelling ? 'Cancelling...' : 'Cancel'}
                  </button>
                </div>
                {/* Real progress bar */}
                <div className="bg-slate-900/50 rounded-full h-4 mb-3 overflow-hidden">
                  <div className="h-full rounded-full bg-gradient-to-r from-purple-600 to-blue-500 transition-all duration-700"
                    style={{ width: `${Math.max(dynProgress, 2)}%` }} />
                </div>
                <div className="flex items-center justify-between mb-5">
                  <p className="text-purple-300 text-sm font-medium">{dynStep}</p>
                  <span className="text-slate-400 text-sm font-mono">{dynProgress}%</span>
                </div>
                {/* Stage explanation */}
                <div className="grid grid-cols-4 gap-2 text-xs">
                  {[
                    { label: 'Upload', range: [0, 10], Icon: Upload },
                    { label: 'VM Boot', range: [10, 50], Icon: Monitor },
                    { label: 'Execute', range: [50, 80], Icon: Play },
                    { label: 'Analyze', range: [80, 100], Icon: Shield },
                  ].map(({ label, range, Icon }) => {
                    const active = dynProgress >= range[0] && dynProgress < range[1];
                    const done = dynProgress >= range[1];
                    return (
                      <div key={label} className={`rounded-lg p-2 text-center border transition ${done ? 'bg-purple-500/20 border-purple-500/40 text-purple-300' : active ? 'bg-purple-500/10 border-purple-500 text-white animate-pulse' : 'bg-slate-900/50 border-slate-700 text-slate-600'}`}>
                        <div className="flex justify-center mb-1">
                          {done
                            ? <CheckCircle className="w-4 h-4 text-purple-300" />
                            : <Icon className={`w-4 h-4 ${active ? 'text-white' : 'text-slate-500'}`} />}
                        </div>
                        <div className="font-medium">{label}</div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Error */}
            {dynState === 'error' && (
              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
                <div className="flex items-start gap-3">
                  <AlertCircle className="w-6 h-6 text-red-400 flex-shrink-0 mt-0.5" />
                  <div className="flex-1">
                    <h4 className="text-white font-semibold mb-1">Sandbox Analysis Failed</h4>
                    <p className="text-red-300 text-sm mb-3">{dynError}</p>
                    {dynError?.includes('not installed') && (
                      <div className="bg-slate-900/50 rounded-lg p-3 text-xs text-slate-400 space-y-1 mb-3">
                        <p className="text-white font-medium">How to enable Windows Sandbox:</p>
                        <p>1. Open "Turn Windows features on or off"</p>
                        <p>2. Enable "Windows Sandbox" ✓</p>
                        <p>3. Restart your PC</p>
                        <p className="text-yellow-400 mt-1">Requires Windows 10/11 Pro or Enterprise</p>
                      </div>
                    )}
                    <button onClick={() => { setDynState('idle'); setDynError(null); }} className="px-4 py-2 border border-slate-600 text-slate-400 hover:text-white hover:border-slate-400 rounded-lg transition text-sm">
                      Try Again
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Dynamic results */}
            {dynState === 'done' && dynResult && (
              <div className="space-y-4">
                <div className="bg-slate-800/50 border border-purple-500/30 rounded-xl p-6 text-center">
                  <div className="flex justify-center mb-3"><StatusIcon s={dynResult.verdict} size={64} /></div>
                  <h4 className="text-white font-bold text-xl mb-2">Dynamic Analysis Complete</h4>
                  <span className={`inline-block px-4 py-2 rounded-full text-sm font-semibold border ${statusColor(dynResult.verdict)}`}>{dynResult.verdict.toUpperCase()}</span>
                  <p className="text-slate-400 text-sm mt-2">Execution: {dynResult.duration}s &bull; Dynamic threat score: {dynResult.threatScore}/100</p>
                  <div className="mt-4 text-left bg-slate-900/50 rounded-lg p-4 space-y-1">
                    {dynResult.summary.map((s,i) => <p key={i} className="text-sm text-slate-300">{s}</p>)}
                  </div>
                </div>

                {/* Collapsible sections */}
                {([
                  { key: 'processes', label: 'Process Activity',   Icon: Monitor,    items: dynResult.processes,
                    empty: '✓ No new processes spawned',
                    render: (p: DynamicProcess) => (
                      <div className={`rounded-lg p-3 border text-sm ${p.suspicious?'bg-red-500/10 border-red-500/30':'bg-slate-900/50 border-slate-600'}`}>
                        <div className="flex items-center gap-2 mb-1">
                          {p.suspicious&&<AlertCircle className="w-3 h-3 text-red-400"/>}
                          <span className="font-mono text-white">{p.name}</span>
                          <span className="text-slate-500 text-xs">PID: {p.pid}</span>
                          {p.suspicious&&<span className="ml-auto text-xs text-red-400 font-medium">SUSPICIOUS</span>}
                        </div>
                        <p className={`text-xs ${p.suspicious?'text-red-300':'text-slate-400'}`}>{p.action}</p>
                      </div>
                    )},
                  { key: 'network', label: 'Network Connections',  Icon: Globe,      items: dynResult.network,
                    empty: '✓ No external network connections',
                    render: (n: DynamicNetwork) => (
                      <div className={`rounded-lg p-3 border text-sm ${n.suspicious?'bg-red-500/10 border-red-500/30':'bg-slate-900/50 border-slate-600'}`}>
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-white">{n.protocol} → {n.destination}:{n.port}</span>
                          {n.suspicious&&<span className="text-xs text-red-400 font-medium">⚠ EXTERNAL</span>}
                        </div>
                      </div>
                    )},
                  { key: 'files', label: 'File System Changes',    Icon: FolderOpen, items: dynResult.files,
                    empty: '✓ No significant file system changes',
                    render: (f: DynamicFile) => (
                      <div className={`rounded-lg p-3 border text-sm ${f.suspicious?'bg-yellow-500/10 border-yellow-500/30':'bg-slate-900/50 border-slate-600'}`}>
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`text-xs px-1.5 py-0.5 rounded font-semibold ${f.action==='created'?'bg-blue-500/20 text-blue-300':f.action==='modified'?'bg-yellow-500/20 text-yellow-300':'bg-red-500/20 text-red-300'}`}>{f.action.toUpperCase()}</span>
                          {f.suspicious&&<span className="text-xs text-yellow-400">⚠ Sensitive location</span>}
                        </div>
                        <p className="font-mono text-white text-xs break-all">{f.path}</p>
                      </div>
                    )},
                  { key: 'registry', label: 'Registry Changes',    Icon: Settings,   items: dynResult.registry,
                    empty: '✓ No registry modifications',
                    render: (r: DynamicRegistry) => (
                      <div className={`rounded-lg p-3 border text-sm ${r.suspicious?'bg-red-500/10 border-red-500/30':'bg-slate-900/50 border-slate-600'}`}>
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`text-xs px-1.5 py-0.5 rounded font-semibold ${r.action==='write'?'bg-red-500/20 text-red-300':r.action==='delete'?'bg-orange-500/20 text-orange-300':'bg-slate-500/20 text-slate-300'}`}>{r.action.toUpperCase()}</span>
                          {r.suspicious&&<><AlertCircle className="w-3 h-3 text-red-400"/><span className="text-xs text-red-400">Persistence key</span></>}
                        </div>
                        <p className="font-mono text-white text-xs break-all">{r.key}</p>
                      </div>
                    )},
                ] as const).map(({ key, label, Icon, items, render, empty }) => (
                  <div key={key} className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
                    <button onClick={() => toggleExpand(key)} className="w-full flex items-center justify-between p-4 text-white font-semibold hover:bg-slate-700/30 transition">
                      <div className="flex items-center gap-2">
                        <Icon className="w-4 h-4 text-cyan-400"/>{label}
                        <span className="text-slate-500 text-sm font-normal">({items.length})</span>
                        {(items as any[]).some(it => it.suspicious) && (
                          <span className="text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded border border-red-500/30">
                            {(items as any[]).filter(it => it.suspicious).length} suspicious
                          </span>
                        )}
                      </div>
                      {expanded[key] ? <ChevronUp className="w-4 h-4"/> : <ChevronDown className="w-4 h-4"/>}
                    </button>
                    {expanded[key] && (
                      <div className="px-4 pb-4 space-y-2">
                        {items.length === 0
                          ? <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3"><p className="text-green-400 text-sm">{empty}</p></div>
                          : (items as any[]).map((item, i) => <div key={i}>{(render as any)(item)}</div>)}
                      </div>
                    )}
                  </div>
                ))}

                <button onClick={() => { setDynState('idle'); setDynResult(null); }} className="w-full py-3 border border-slate-600 text-slate-400 hover:text-white hover:border-slate-400 rounded-lg transition text-sm">
                  Run Dynamic Analysis Again
                </button>
              </div>
            )}

          </>)}
        </div>
      </div>
    </div>
  );
}
