import { useEffect, useMemo, useState } from 'react';
import { ShieldBan, Plus, Trash2, RefreshCw, Link as LinkIcon } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

type BlockRule = {
  id: number;
  pattern: string;
  enabled: boolean;
  note?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
};

const API_BASE = 'http://127.0.0.1:8000';
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

  if (value.includes('*')) {
    return value;
  }
  return `*.${value}`;
}

export function AccessControlView() {
  const { token } = useAuth();
  const [rules, setRules] = useState<BlockRule[]>([]);
  const [newDomain, setNewDomain] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const sortedRules = useMemo(
    () => [...rules].sort((a, b) => a.pattern.localeCompare(b.pattern)),
    [rules]
  );

  const fetchRules = async (showLoader = true) => {
    if (!token) {
      return;
    }
    try {
      if (showLoader) {
        setLoading(true);
      }
      const res = await fetch(`${API_BASE}/gateway/blocklist`, {
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
      const res = await fetch(`${API_BASE}/gateway/blocklist`, {
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
      const res = await fetch(`${API_BASE}/gateway/blocklist/${rule.id}`, {
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
      const res = await fetch(`${API_BASE}/gateway/blocklist/${ruleId}`, {
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
    <div className="flex-1 bg-slate-900 global-scroll">
      <div className="p-8 max-w-6xl mx-auto">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-8">
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

        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-6">
          <label className="block text-slate-300 text-sm mb-2">Add domain or URL</label>
          <div className="flex flex-col md:flex-row gap-3">
            <div className="relative flex-1">
              <LinkIcon className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                placeholder="example.com or https://example.com/page"
                className="w-full pl-10 pr-4 py-2 bg-slate-900/70 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
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
        </div>

        {error && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 mb-6 text-red-300">
            {error}
          </div>
        )}

        <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-700 flex items-center gap-2 text-slate-200">
            <ShieldBan className="w-5 h-5 text-cyan-400" />
            Active Block Rules ({sortedRules.length})
          </div>

          {loading ? (
            <div className="p-6 text-slate-400">Loading rules...</div>
          ) : sortedRules.length === 0 ? (
            <div className="p-6 text-slate-400">No blocked domains configured yet.</div>
          ) : (
            <div className="divide-y divide-slate-700">
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
