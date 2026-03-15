import { useMemo, useState } from 'react';
import {
  AlertCircle,
  AlertTriangle,
  CalendarDays,
  CheckCircle,
  Link2,
  Mail,
  Paperclip,
  Search,
  Shield,
  Upload,
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { apiUrl } from '../config/api';

type EmailUrlResult = {
  url: string;
  status: 'clean' | 'malicious' | 'suspicious';
  threat_score: number;
  matched_feed?: boolean;
};

type EmailAttachmentResult = {
  filename: string;
  content_type?: string;
  size?: number;
  status: 'clean' | 'malicious' | 'suspicious';
  threat_score: number;
  risk_category?: string;
};

type EmailScanResult = {
  status: 'clean' | 'malicious' | 'suspicious';
  threat_score: number;
  target: string;
  details: {
    subject: string;
    headers: {
      from?: string;
      from_name?: string;
      to?: string;
      to_name?: string;
      reply_to?: string;
      from_domain?: string;
      reply_to_domain?: string;
      return_path?: string;
      date?: string;
      message_id?: string;
      mailed_by?: string;
      signed_by?: string;
      security?: string;
    };
    authentication: {
      spf?: string;
      dkim?: string;
      dmarc?: string;
    };
    body_summary: {
      preview?: string;
      plain_text_chars?: number;
      html_chars?: number;
      has_html?: boolean;
    };
    url_analysis: {
      count: number;
      malicious: number;
      suspicious: number;
      results: EmailUrlResult[];
      html_link_mismatches?: { href: string; text: string; mismatch: boolean }[];
    };
    attachment_analysis: {
      count: number;
      malicious: number;
      suspicious: number;
      results: EmailAttachmentResult[];
    };
    phishing_signals: string[];
    overall_threat_score: number;
  };
};

const statusClass = (status?: string) => {
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

const authBadge = (value?: string) => {
  if (value === 'pass') return 'text-emerald-300 bg-emerald-500/10 border-emerald-500/30';
  if (value === 'fail' || value === 'softfail') return 'text-red-300 bg-red-500/10 border-red-500/30';
  if (value === 'unknown' || value === 'none') return 'text-amber-300 bg-amber-500/10 border-amber-500/30';
  return 'text-slate-300 bg-slate-500/10 border-slate-500/30';
};

const formatBytes = (bytes?: number) => {
  if (!Number.isFinite(bytes)) return 'N/A';
  const value = Number(bytes);
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(2)} MB`;
};

const InfoField = ({ label, value, secondary }: { label: string; value: string; secondary?: string }) => (
  <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-4 min-w-0">
    <p className="text-slate-400 text-xs mb-2 uppercase tracking-[0.24em]">{label}</p>
    <p className="text-white font-semibold break-words">{value}</p>
    {secondary ? <p className="text-slate-500 text-xs mt-2 break-words">{secondary}</p> : null}
  </div>
);

export function EmailScannerPanel() {
  const { token } = useAuth();
  const [emailFile, setEmailFile] = useState<File | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<EmailScanResult | null>(null);

  const resultIcon = useMemo(() => {
    if (!result) return null;
    if (result.status === 'clean') return <CheckCircle className="w-16 h-16 text-green-400" />;
    if (result.status === 'malicious') return <AlertCircle className="w-16 h-16 text-red-400" />;
    return <AlertTriangle className="w-16 h-16 text-yellow-400" />;
  }, [result]);

  const scanEmail = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!token) {
      setError('You must be signed in.');
      return;
    }
    if (!emailFile) {
      setError('Upload an .eml email file to continue.');
      return;
    }

    setScanning(true);
    setError(null);
    setResult(null);

    try {
      const formData = new FormData();
      formData.append('email_file', emailFile);

      const response = await fetch(apiUrl('/email-scan'), {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload?.detail || payload?.message || 'Email scan failed');
      }

      setResult({
        status: payload.status || 'clean',
        threat_score: payload.threat_score || 0,
        target: payload.target || 'Email',
        details: payload.details,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Email scan failed');
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-slate-800/50 border border-slate-700 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3 text-fuchsia-300">
            <Mail className="w-4 h-4" />
            <p className="text-sm font-semibold">Email Threat Analysis</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
            <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
              <p className="text-slate-400">Header Checks</p>
              <p className="text-white font-semibold">Sender Identity</p>
              <p className="text-slate-500 text-xs mt-1">From, Reply-To, mailed-by, signed-by, auth results</p>
            </div>
            <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
              <p className="text-slate-400">URL Reuse</p>
              <p className="text-white font-semibold">Link Extraction</p>
              <p className="text-slate-500 text-xs mt-1">Every extracted link is re-scored by the URL engine</p>
            </div>
            <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-3">
              <p className="text-slate-400">Attachment Reuse</p>
              <p className="text-white font-semibold">File Analysis</p>
              <p className="text-slate-500 text-xs mt-1">Attachments inherit the static file analysis pipeline</p>
            </div>
          </div>
        </div>
        <div className="bg-gradient-to-br from-fuchsia-500/10 to-purple-500/10 border border-fuchsia-500/30 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2 text-fuchsia-300">
            <Shield className="w-4 h-4" />
            <p className="text-sm font-semibold">What This Catches</p>
          </div>
          <ul className="space-y-2 text-sm text-slate-200">
            <li>- Sender spoofing and Reply-To mismatch</li>
            <li>- Credential theft and urgency wording</li>
            <li>- Malicious or suspicious extracted URLs</li>
            <li>- Risky attachments such as scripts, archives, or executables</li>
          </ul>
        </div>
      </div>

      <form onSubmit={scanEmail} className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 space-y-4">
        <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-5">
          <div className="flex items-center gap-2 mb-3 text-slate-200">
            <Upload className="w-4 h-4 text-fuchsia-400" />
            <p className="font-medium">Upload .eml Email</p>
          </div>
          <input
            type="file"
            accept=".eml,message/rfc822"
            onChange={(e) => setEmailFile(e.target.files?.[0] ?? null)}
            className="block w-full text-sm text-slate-300 file:mr-4 file:rounded-lg file:border-0 file:bg-fuchsia-500/20 file:px-4 file:py-2 file:text-fuchsia-200 hover:file:bg-fuchsia-500/30"
          />
          <div className="mt-3 rounded-lg border border-slate-700 bg-slate-950/70 px-4 py-3 text-sm text-slate-300">
            Upload the original `.eml` file only. Raw pasted email has been removed from the UI to keep the analysis format stable and locale-independent.
          </div>
        </div>

        <div className="flex items-center justify-between gap-4">
          <div className="text-xs text-slate-500">
            The scanner now accepts email files only. This preserves headers, MIME structure, body formatting, and attachments.
          </div>
          <button
            type="submit"
            disabled={scanning}
            className="px-6 py-3 rounded-lg bg-gradient-to-r from-fuchsia-600 to-purple-600 text-white font-semibold hover:from-fuchsia-700 hover:to-purple-700 disabled:opacity-50 transition flex items-center gap-2"
          >
            <Search className="w-4 h-4" />
            {scanning ? 'Scanning Email...' : 'Scan Email'}
          </button>
        </div>
      </form>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
          <div className="flex items-center gap-2 text-red-400">
            <AlertCircle className="w-5 h-5" />
            <p className="font-medium">{error}</p>
          </div>
        </div>
      )}

      {result && (
        <div className="space-y-6">
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-8 text-center">
            <div className="flex justify-center mb-4">{resultIcon}</div>
            <h3 className="text-2xl font-bold text-white mb-2">Email Scan Complete</h3>
            <p className="text-slate-400 mb-3 break-words">{result.target}</p>
            <span className={`inline-block px-4 py-2 rounded-full text-sm font-semibold border ${statusClass(result.status)}`}>
              {result.status.toUpperCase()}
            </span>
            <div className="mt-5">
              <p className="text-slate-400 text-sm mb-2">Combined Phishing Score</p>
              <div className="flex items-center justify-center gap-3">
                <div className="flex-1 max-w-md bg-slate-900/50 rounded-full h-3">
                  <div
                    className={`h-full rounded-full ${
                      result.threat_score >= 70 ? 'bg-red-500' : result.threat_score >= 35 ? 'bg-yellow-500' : 'bg-green-500'
                    }`}
                    style={{ width: `${result.threat_score}%` }}
                  />
                </div>
                <span className="text-white font-bold text-xl min-w-[3rem]">{result.threat_score}/100</span>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
              <h4 className="text-white font-semibold mb-4">Sender & Authentication</h4>
              <div className="space-y-3 text-sm">
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-4">
                  <p className="text-slate-400 text-xs mb-2 uppercase tracking-[0.24em]">Subject</p>
                  <p className="text-white text-lg font-semibold leading-relaxed break-words">
                    {result.details.subject || '(No subject)'}
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <InfoField
                    label="From"
                    value={result.details.headers.from || 'Unknown'}
                    secondary={result.details.headers.from_name || result.details.headers.from_domain}
                  />
                  <InfoField
                    label="Reply-To"
                    value={result.details.headers.reply_to || 'Not set'}
                    secondary={result.details.headers.reply_to_domain}
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <InfoField label="Date" value={result.details.headers.date || 'Unknown'} />
                  <InfoField label="Security" value={result.details.headers.security || 'Not provided'} />
                </div>

                {(result.details.headers.mailed_by || result.details.headers.signed_by) && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <InfoField label="Mailed By" value={result.details.headers.mailed_by || 'Not provided'} />
                    <InfoField label="Signed By" value={result.details.headers.signed_by || 'Not provided'} />
                  </div>
                )}

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-4">
                    <p className="text-slate-400 text-xs mb-2 uppercase tracking-[0.24em]">SPF</p>
                    <span className={`inline-flex rounded-full border px-3 py-1 text-sm font-semibold uppercase ${authBadge(result.details.authentication.spf)}`}>
                      {result.details.authentication.spf || 'unknown'}
                    </span>
                  </div>
                  <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-4">
                    <p className="text-slate-400 text-xs mb-2 uppercase tracking-[0.24em]">DKIM</p>
                    <span className={`inline-flex rounded-full border px-3 py-1 text-sm font-semibold uppercase ${authBadge(result.details.authentication.dkim)}`}>
                      {result.details.authentication.dkim || 'unknown'}
                    </span>
                  </div>
                  <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-4">
                    <p className="text-slate-400 text-xs mb-2 uppercase tracking-[0.24em]">DMARC</p>
                    <span className={`inline-flex rounded-full border px-3 py-1 text-sm font-semibold uppercase ${authBadge(result.details.authentication.dmarc)}`}>
                      {result.details.authentication.dmarc || 'unknown'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
              <h4 className="text-white font-semibold mb-4">Body & Phishing Signals</h4>
              <div className="space-y-3">
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-4">
                  <div className="flex items-center justify-between gap-3 mb-3">
                    <p className="text-slate-400 text-xs uppercase tracking-[0.24em]">Preview</p>
                    <div className="text-xs text-slate-500 text-right">
                      <span>{result.details.body_summary.plain_text_chars || 0} text chars</span>
                      <span className="mx-2">•</span>
                      <span>{result.details.body_summary.has_html ? 'HTML present' : 'No HTML'}</span>
                    </div>
                  </div>
                  <div className="max-h-56 overflow-y-auto rounded-lg bg-slate-950/70 px-4 py-3 text-[15px] leading-8 text-slate-100 whitespace-pre-wrap break-words">
                    {result.details.body_summary.preview || 'No preview available.'}
                  </div>
                </div>

                {result.details.phishing_signals.length > 0 ? (
                  <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                    <p className="text-yellow-300 font-semibold text-sm mb-3 uppercase tracking-[0.24em]">Signals Detected</p>
                    <ul className="space-y-2">
                      {result.details.phishing_signals.map((signal, idx) => (
                        <li key={idx} className="text-sm text-slate-100 break-words">- {signal}</li>
                      ))}
                    </ul>
                  </div>
                ) : (
                  <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                    <p className="text-green-300 text-sm font-medium">No phishing heuristics were triggered.</p>
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
              <div className="flex items-center gap-2 mb-4">
                <Link2 className="w-4 h-4 text-fuchsia-400" />
                <h4 className="text-white font-semibold">Extracted URLs</h4>
              </div>
              {result.details.url_analysis.results.length === 0 ? (
                <p className="text-slate-400 text-sm">No URLs extracted from this email.</p>
              ) : (
                <div className="space-y-2">
                  {result.details.url_analysis.results.map((item, idx) => (
                    <div key={`${item.url}-${idx}`} className="rounded-lg border border-slate-700 bg-slate-900/50 p-3">
                      <div className="flex items-start justify-between gap-3">
                        <p className="text-sm text-slate-100 break-words min-w-0">{item.url}</p>
                        <span className={`px-2 py-1 rounded-full text-xs font-semibold border whitespace-nowrap ${statusClass(item.status)}`}>
                          {item.status}
                        </span>
                      </div>
                      <div className="mt-2 flex items-center justify-between text-xs gap-4">
                        <span className="text-slate-400">Threat score: <span className="text-white">{item.threat_score}/100</span></span>
                        <span className={item.matched_feed ? 'text-red-400' : 'text-slate-500'}>
                          {item.matched_feed ? 'Threat feed hit' : 'No feed hit'}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
              <div className="flex items-center gap-2 mb-4">
                <Paperclip className="w-4 h-4 text-fuchsia-400" />
                <h4 className="text-white font-semibold">Attachments</h4>
              </div>
              {result.details.attachment_analysis.results.length === 0 ? (
                <p className="text-slate-400 text-sm">No attachments detected.</p>
              ) : (
                <div className="space-y-2">
                  {result.details.attachment_analysis.results.map((item, idx) => (
                    <div key={`${item.filename}-${idx}`} className="rounded-lg border border-slate-700 bg-slate-900/50 p-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <p className="text-sm text-slate-100 break-words">{item.filename}</p>
                          <p className="text-xs text-slate-500 break-words">{item.content_type || 'application/octet-stream'} • {formatBytes(item.size)}</p>
                        </div>
                        <span className={`px-2 py-1 rounded-full text-xs font-semibold border whitespace-nowrap ${statusClass(item.status)}`}>
                          {item.status}
                        </span>
                      </div>
                      <div className="mt-2 flex items-center justify-between text-xs gap-4">
                        <span className="text-slate-400">Threat score: <span className="text-white">{item.threat_score}/100</span></span>
                        <span className="text-slate-500 capitalize">{item.risk_category || 'unknown'}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
