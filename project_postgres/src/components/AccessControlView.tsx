import { useEffect, useMemo, useState } from 'react';
import { ShieldBan, Plus, Trash2, RefreshCw, Link as LinkIcon } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { apiUrl } from '../config/api';

type BlockRule = {
  id: number;
  pattern: string;
  enabled: boolean;
  note?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
};

type SuggestionItem = {
  id: string;
  label: string;
  pattern: string;
  description: string;
  source?: string;
};

const QUICK_SUGGESTIONS: SuggestionItem[] = [
  { id: 'quick-youtube', label: 'YouTube', pattern: 'youtube.com', description: 'Fast local suggestion.', source: 'featured' },
  { id: 'quick-youtube-api', label: 'YouTube API / DNS', pattern: 'youtubei.googleapis.com', description: 'Fast local suggestion.', source: 'featured' },
  { id: 'quick-facebook', label: 'Facebook', pattern: 'facebook.com', description: 'Fast local suggestion.', source: 'featured' },
  { id: 'quick-instagram', label: 'Instagram', pattern: 'instagram.com', description: 'Fast local suggestion.', source: 'featured' },
  { id: 'quick-discord', label: 'Discord', pattern: 'discord.com', description: 'Fast local suggestion.', source: 'featured' },
  { id: 'quick-openai', label: 'OpenAI', pattern: 'openai.com', description: 'Fast local suggestion.', source: 'featured' },
  { id: 'quick-chatgpt', label: 'ChatGPT', pattern: 'chatgpt.com', description: 'Fast local suggestion.', source: 'featured' },
  { id: 'quick-github', label: 'GitHub', pattern: 'github.com', description: 'Fast local suggestion.', source: 'featured' },
  { id: 'quick-linkedin', label: 'LinkedIn', pattern: 'linkedin.com', description: 'Fast local suggestion.', source: 'featured' },
  { id: 'quick-whatsapp', label: 'WhatsApp', pattern: 'web.whatsapp.com', description: 'Fast local suggestion.', source: 'featured' },
];

const SUGGESTION_CACHE = new Map<string, SuggestionItem[]>();

const DOMAIN_SHORTCUTS: Record<string, string> = {
  yt: 'youtube',
  youtube: 'youtube',
  fb: 'facebook',
  facebook: 'facebook',
  ig: 'instagram',
  insta: 'instagram',
  instagram: 'instagram',
  wa: 'whatsapp',
  whatsapp: 'whatsapp',
  tw: 'twitter',
  twitter: 'twitter',
  x: 'twitter',
};

const SERVICE_DOMAIN_HINTS: Record<string, string[]> = {
  youtube: ['youtube', 'youtu.be', 'ytimg', 'googlevideo', 'yt3'],
  facebook: ['facebook', 'fbcdn', 'fbsbx', 'messenger'],
  instagram: ['instagram', 'cdninstagram'],
  twitter: ['twitter', 'twimg', 'x.com'],
  whatsapp: ['whatsapp', 'whatsapp.net', 'wa.me'],
};

function resolveServiceBundle(value: string): string | null {
  const normalized = value.trim().toLowerCase().replace(/^\.+|\.+$/g, '');
  if (!normalized) {
    return null;
  }

  if (DOMAIN_SHORTCUTS[normalized]) {
    return DOMAIN_SHORTCUTS[normalized];
  }

  const trimmed = normalized.replace(/^\*\./, '').replace(/\*/g, '');
  for (const [service, hints] of Object.entries(SERVICE_DOMAIN_HINTS)) {
    if (trimmed === service) {
      return service;
    }
    if (
      hints.some((hint) => trimmed === hint || trimmed.endsWith(`.${hint}`) || trimmed.includes(hint))
    ) {
      return service;
    }
  }

  return null;
}

function normalizePattern(input: string): string | null {
  let value = input.trim().toLowerCase();
  if (!value) {
    return null;
  }

  if (value.startsWith('http://') || value.startsWith('https://')) {
    try {
      value = new URL(value).hostname;
    } catch {
      return null;
    }
  }

  value = value.split('/')[0].trim().replace(/^\.+|\.+$/g, '').replace(/^www\./, '');
  if (!value) {
    return null;
  }

  const serviceBundle = resolveServiceBundle(value);
  if (serviceBundle) {
    return `*${serviceBundle}*`;
  }

  if (value.includes('*')) {
    return value;
  }
  if (value.includes('.')) {
    return `*.${value}`;
  }

  const shortcut = DOMAIN_SHORTCUTS[value] || value;
  return `*${shortcut}*`;
}

function quickSuggestions(query: string): SuggestionItem[] {
  const q = query.trim().toLowerCase();
  if (q.length < 2) return [];
  return QUICK_SUGGESTIONS.filter((item) =>
    item.label.toLowerCase().includes(q) || item.pattern.toLowerCase().includes(q)
  ).slice(0, 5);
}

function mergeSuggestions(primary: SuggestionItem[], secondary: SuggestionItem[]): SuggestionItem[] {
  const merged: SuggestionItem[] = [];
  const seen = new Set<string>();

  for (const item of [...primary, ...secondary]) {
    const key = (normalizePattern(item.pattern) || item.pattern).toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    merged.push(item);
  }

  return merged.slice(0, 8);
}

export function AccessControlView() {
  const { token } = useAuth();
  const [rules, setRules] = useState<BlockRule[]>([]);
  const [newDomain, setNewDomain] = useState('');
  const [suggestions, setSuggestions] = useState<SuggestionItem[]>([]);
  const [suggesting, setSuggesting] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const sortedRules = useMemo(
    () => [...rules].sort((a, b) => a.pattern.localeCompare(b.pattern)),
    [rules]
  );

  const suggestionMatches = useMemo(() => {
    const existingPatterns = new Set(rules.map((rule) => rule.pattern.toLowerCase()));
    return suggestions.filter((item) => {
      const normalizedPattern = normalizePattern(item.pattern)?.toLowerCase();
      return !(normalizedPattern && existingPatterns.has(normalizedPattern));
    });
  }, [rules, suggestions]);

  const fetchRules = async (showLoader = true) => {
    if (!token) {
      return;
    }
    try {
      if (showLoader) {
        setLoading(true);
      }
      const res = await fetch(apiUrl('/gateway/blocklist'), {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      if (!res.ok) {
        throw new Error('Failed to load blocklist');
      }
      const data = (await res.json()) as BlockRule[];
      setRules(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load blocklist');
    } finally {
      if (showLoader) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    fetchRules(true);
  }, [token]);

  useEffect(() => {
    if (!token) {
      setSuggestions([]);
      return;
    }

    const query = newDomain.trim();
    if (query.length < 2) {
      setSuggestions([]);
      return;
    }

    const instant = quickSuggestions(query);
    setSuggestions(instant);

    const cached = SUGGESTION_CACHE.get(query.toLowerCase());
    if (cached) {
      setSuggestions(mergeSuggestions(instant, cached));
      setSuggesting(false);
      return;
    }

    let cancelled = false;
    const timeoutId = window.setTimeout(async () => {
      try {
        setSuggesting(true);
        const res = await fetch(apiUrl(`/gateway/blocklist/suggest?q=${encodeURIComponent(query)}`), {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (!res.ok) {
          throw new Error('Failed to load suggestions');
        }
        const data = (await res.json()) as SuggestionItem[];
        if (!cancelled) {
          SUGGESTION_CACHE.set(query.toLowerCase(), data);
          setSuggestions(mergeSuggestions(instant, data));
        }
      } catch {
        if (!cancelled) {
          setSuggestions(instant);
        }
      } finally {
        if (!cancelled) {
          setSuggesting(false);
        }
      }
    }, 120);

    return () => {
      cancelled = true;
      window.clearTimeout(timeoutId);
    };
  }, [newDomain, token]);

  const addRule = async () => {
    if (!token) {
      return;
    }
    const pattern = normalizePattern(newDomain);
    if (!pattern) {
      setError('Please enter a valid domain or URL');
      return;
    }

    try {
      setSaving(true);
      const res = await fetch(apiUrl('/gateway/blocklist'), {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          pattern,
          enabled: true,
          note: 'Added from access control panel',
        }),
      });
      if (!res.ok) {
        const detail = await res.json().catch(() => ({}));
        throw new Error(detail.detail || 'Failed to add block rule');
      }
      setNewDomain('');
      setSuggestions([]);
      await fetchRules(false);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add block rule');
    } finally {
      setSaving(false);
    }
  };

  const toggleRule = async (rule: BlockRule) => {
    if (!token) {
      return;
    }
    try {
      const res = await fetch(apiUrl(`/gateway/blocklist/${rule.id}`), {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ enabled: !rule.enabled }),
      });
      if (!res.ok) {
        throw new Error('Failed to update rule');
      }
      await fetchRules(false);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update rule');
    }
  };

  const deleteRule = async (ruleId: number) => {
    if (!token) {
      return;
    }
    try {
      const res = await fetch(apiUrl(`/gateway/blocklist/${ruleId}`), {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      if (!res.ok) {
        throw new Error('Failed to remove rule');
      }
      await fetchRules(false);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove rule');
    }
  };

  return (
    <div className="flex h-full flex-col overflow-hidden bg-slate-900">
      <div className="mx-auto flex min-h-0 w-full max-w-6xl flex-1 flex-col p-8">
        <div className="mb-8 flex shrink-0 flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-3xl font-bold text-white mb-2">Website Access Control</h2>
            <p className="text-slate-400">Manage blocked domains for all devices using your proxy.</p>
          </div>
          <button
            onClick={() => fetchRules(false)}
            className="px-4 py-2 bg-slate-800 border border-slate-700 text-slate-200 rounded-lg hover:bg-slate-700 flex items-center gap-2"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>

        <div className="mb-6 shrink-0 rounded-xl border border-slate-700 bg-slate-800/50 p-5">
          <label className="block text-slate-300 text-sm mb-2">Add domain or URL</label>
          <div className="flex flex-col md:flex-row gap-3">
            <div className="relative flex-1">
              <LinkIcon className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    void addRule();
                  }
                }}
                placeholder="example.com or https://example.com/page"
                className="w-full pl-10 pr-4 py-2 bg-slate-900/70 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
              {(suggestionMatches.length > 0 || suggesting) && (
                <div className="absolute z-20 left-0 right-0 mt-2 bg-slate-900 border border-slate-700 rounded-xl shadow-2xl overflow-hidden">
                  <div className="px-3 py-2 border-b border-slate-700 text-[11px] uppercase tracking-wide text-slate-400 flex items-center justify-between gap-2">
                    <span>Suggested websites</span>
                    {suggesting && <span className="text-[10px] text-cyan-300 normal-case">Updating live...</span>}
                  </div>
                  {suggestionMatches.length > 0 ? (
                    <div className="divide-y divide-slate-800">
                      {suggestionMatches.map((item) => (
                        <button
                          key={item.id}
                          type="button"
                          onClick={() => setNewDomain(item.pattern)}
                          className="w-full text-left px-3 py-3 hover:bg-slate-800/80 transition"
                        >
                          <div className="flex items-center justify-between gap-3">
                            <div>
                              <p className="text-sm font-medium text-slate-100">{item.label}</p>
                              <p className="text-xs text-cyan-300 mt-0.5">{item.pattern}</p>
                            </div>
                            <span className="text-[11px] px-2 py-0.5 rounded-full border border-slate-600 text-slate-300">
                              {item.source === 'featured' ? 'Popular' : 'Live'}
                            </span>
                          </div>
                          <p className="text-xs text-slate-400 mt-1">{item.description}</p>
                        </button>
                      ))}
                    </div>
                  ) : (
                    !suggesting && <div className="px-3 py-3 text-sm text-slate-400">No suggestions found yet.</div>
                  )}
                </div>
              )}
            </div>
            <button
              onClick={addRule}
              disabled={saving}
              className="px-5 py-2 bg-cyan-500 text-white rounded-lg hover:bg-cyan-600 disabled:opacity-50 flex items-center gap-2"
            >
              <Plus className="w-4 h-4" />
              Add Block
            </button>
          </div>
          <p className="text-xs text-slate-500 mt-2">
            Input is normalized to wildcard format (example: <code>*.domain.com</code>).
          </p>
          <p className="text-xs text-slate-500 mt-1">
            Start typing a famous website like <code>you</code>, <code>discord</code>, or <code>openai</code> to get live suggestions.
          </p>
        </div>

        {error && (
          <div className="mb-6 shrink-0 rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-red-300">
            {error}
          </div>
        )}

        <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-xl border border-slate-700 bg-slate-800/50">
          <div className="flex shrink-0 items-center gap-2 border-b border-slate-700 px-5 py-4 text-slate-200">
            <ShieldBan className="w-5 h-5 text-cyan-400" />
            Active Block Rules ({sortedRules.length})
          </div>

          {loading ? (
            <div className="p-6 text-slate-400">Loading rules...</div>
          ) : sortedRules.length === 0 ? (
            <div className="p-6 text-slate-400">No blocked domains configured yet.</div>
          ) : (
            <div className="min-h-0 flex-1 overflow-y-auto divide-y divide-slate-700 pr-1 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-slate-700 [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar]:w-2">
              {sortedRules.map((rule) => (
                <div key={rule.id} className="p-4 flex flex-col md:flex-row md:items-center gap-3 md:justify-between">
                  <div>
                    <p className="text-slate-100 font-medium">{rule.pattern}</p>
                    <p className="text-xs text-slate-500">{rule.note || 'No note'}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => toggleRule(rule)}
                      className={`px-3 py-1 rounded text-xs font-medium ${
                        rule.enabled ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' : 'bg-slate-700 text-slate-300 border border-slate-600'
                      }`}
                    >
                      {rule.enabled ? 'Enabled' : 'Disabled'}
                    </button>
                    <button
                      onClick={() => deleteRule(rule.id)}
                      className="px-3 py-1 rounded text-xs font-medium bg-red-500/15 text-red-300 border border-red-500/30 hover:bg-red-500/25 flex items-center gap-1"
                    >
                      <Trash2 className="w-3 h-3" />
                      Remove
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
