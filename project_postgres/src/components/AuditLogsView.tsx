import { useEffect, useMemo, useState } from "react";
import { FileText, Calendar, User, Filter, Download, Search, ChevronDown, Server, Laptop, ShieldAlert, Activity } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

type AuditLog = {
  id: number;
  user_id: number | null;
  user_email?: string | null;
  user_name?: string | null;
  action: string;
  details: string;
  timestamp: string;
};

type ProxyHealth = {
  running: boolean;
  autostart: boolean;
  listen_host: string;
  listen_port: number;
  connected_devices: number;
  total_events: number;
  started_at: string;
  uptime_seconds: number;
};

type ProxyDevice = {
  device_name: string;
  client_ip: string;
  first_seen: string;
  last_seen: string;
  total_requests: number;
  blocked_requests: number;
  allowed_requests: number;
  methods: Record<string, number>;
  last_host?: string;
};

type ProxyStats = {
  total_events: number;
  unique_clients: number;
  blocked_requests: number;
  allowed_requests: number;
  methods: Record<string, number>;
  requests_by_ip: Record<string, number>;
};

type TrafficMeta = {
  isGateway: boolean;
  protocol: 'HTTP' | 'HTTPS' | 'N/A';
  method: string;
  verdict: 'ALLOW' | 'BLOCK' | 'N/A';
};

const API_BASE = 'http://127.0.0.1:8000';

function parseTrafficMeta(log: AuditLog): TrafficMeta {
  const action = (log.action || '').toUpperCase();
  const details = (log.details || '').toUpperCase();

  const actionMatch = action.match(/GATEWAY\s+(HTTP|HTTPS)\s+([A-Z]+)\s+(ALLOW|BLOCK)/);
  if (actionMatch) {
    return {
      isGateway: true,
      protocol: actionMatch[1] as 'HTTP' | 'HTTPS',
      method: actionMatch[2],
      verdict: actionMatch[3] as 'ALLOW' | 'BLOCK',
    };
  }

  const detailMatch = details.match(/\b(ALLOWED|BLOCKED)\s+(HTTP|HTTPS)\s+([A-Z]+)/);
  if (detailMatch) {
    return {
      isGateway: true,
      protocol: detailMatch[2] as 'HTTP' | 'HTTPS',
      method: detailMatch[3],
      verdict: detailMatch[1] === 'ALLOWED' ? 'ALLOW' : 'BLOCK',
    };
  }

  return { isGateway: false, protocol: 'N/A', method: 'N/A', verdict: 'N/A' };
}

function formatUptime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) {
    return '0m';
  }
  const hrs = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (hrs > 0) {
    return `${hrs}h ${mins}m`;
  }
  return `${mins}m`;
}

export function AuditLogsView() {
  const { token } = useAuth();
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [filteredLogs, setFilteredLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [gatewayError, setGatewayError] = useState<string | null>(null);
  const [health, setHealth] = useState<ProxyHealth | null>(null);
  const [devices, setDevices] = useState<ProxyDevice[]>([]);
  const [stats, setStats] = useState<ProxyStats | null>(null);

  // Filter states
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState<'date' | 'action' | 'user'>('date');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [actionFilter, setActionFilter] = useState<string>('all');
  const [userFilter, setUserFilter] = useState<string>('all');
  const [dateRange, setDateRange] = useState<{ start: string; end: string }>({
    start: '',
    end: ''
  });

  useEffect(() => {
    loadLogs(true);
    loadGatewayData();
  }, [sortBy, sortOrder, token]);

  useEffect(() => {
    if (!token) {
      return;
    }
    const timer = window.setInterval(() => {
      loadLogs(false);
      loadGatewayData();
    }, 3000);
    return () => window.clearInterval(timer);
  }, [sortBy, sortOrder, token]);

  useEffect(() => {
    applyFilters();
  }, [logs, searchTerm, actionFilter, userFilter, dateRange]);

  const loadLogs = async (showLoader: boolean) => {
    try {
      if (showLoader) {
        setLoading(true);
      }
      const params = new URLSearchParams({
        sort_by: sortBy,
        order: sortOrder,
        limit: '500'
      });

      if (!token) {
        throw new Error('No authentication token');
      }

      const res = await fetch(`${API_BASE}/audit?${params}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (!res.ok) {
        throw new Error('Failed to fetch audit logs');
      }
      const data = await res.json();
      setLogs(data);
      setError(null);
    } catch (err) {
      console.error("Failed to load logs:", err);
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      if (showLoader) {
        setLoading(false);
      }
    }
  };

  const loadGatewayData = async () => {
    try {
      if (!token) {
        return;
      }
      const [healthRes, devicesRes, statsRes] = await Promise.all([
        fetch(`${API_BASE}/gateway/proxy/health`, { headers: { Authorization: `Bearer ${token}` } }),
        fetch(`${API_BASE}/gateway/api/devices`, { headers: { Authorization: `Bearer ${token}` } }),
        fetch(`${API_BASE}/gateway/api/stats`, { headers: { Authorization: `Bearer ${token}` } }),
      ]);

      if (!healthRes.ok || !devicesRes.ok || !statsRes.ok) {
        throw new Error('Failed to fetch gateway telemetry');
      }

      const [healthData, devicesData, statsData] = await Promise.all([
        healthRes.json() as Promise<ProxyHealth>,
        devicesRes.json() as Promise<ProxyDevice[]>,
        statsRes.json() as Promise<ProxyStats>,
      ]);

      setHealth(healthData);
      setDevices(devicesData);
      setStats(statsData);
      setGatewayError(null);
    } catch (err) {
      setGatewayError(err instanceof Error ? err.message : 'Failed to fetch gateway telemetry');
    }
  };

  const applyFilters = () => {
    let filtered = [...logs];

    // Search filter
    if (searchTerm) {
      filtered = filtered.filter(log =>
        log.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
        log.details.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    // Action filter
    if (actionFilter !== 'all') {
      filtered = filtered.filter(log => log.action === actionFilter);
    }

    // User filter
    if (userFilter !== 'all') {
      filtered = filtered.filter(log => String(log.user_id ?? '') === userFilter);
    }

    // Date range filter
    if (dateRange.start) {
      const startDate = new Date(dateRange.start);
      startDate.setHours(0, 0, 0, 0);
      filtered = filtered.filter(log =>
        new Date(log.timestamp) >= startDate
      );
    }
    if (dateRange.end) {
      const endDate = new Date(dateRange.end);
      endDate.setHours(23, 59, 59, 999);
      filtered = filtered.filter(log =>
        new Date(log.timestamp) <= endDate
      );
    }

    setFilteredLogs(filtered);
  };

  const exportToExcel = () => {
    const headers = ['ID', 'User', 'User Email', 'Action', 'Protocol', 'Method', 'Decision', 'Details', 'Timestamp'];
    const tsvData = filteredLogs.map(log => [
      log.id,
      log.user_name || (log.user_id === null ? 'System' : `User #${log.user_id}`),
      log.user_email || '',
      log.action,
      parseTrafficMeta(log).protocol,
      parseTrafficMeta(log).method,
      parseTrafficMeta(log).verdict,
      log.details.replace(/\t/g, ' '),
      new Date(log.timestamp).toLocaleString()
    ]);

    const tsvContent = [
      headers.join('\t'),
      ...tsvData.map(row => row.join('\t'))
    ].join('\n');

    const blob = new Blob([tsvContent], { type: 'application/vnd.ms-excel;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit_logs_${new Date().toISOString().split('T')[0]}.xls`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const clearFilters = () => {
    setSearchTerm('');
    setActionFilter('all');
    setUserFilter('all');
    setDateRange({ start: '', end: '' });
  };

  const uniqueActions = Array.from(new Set(logs.map(log => log.action)));
  const uniqueUsers = Array.from(new Set(logs.map(log => log.user_id).filter((id): id is number => id !== null)));
  const methodSummary = useMemo(() => {
    if (!stats) {
      return [];
    }
    return Object.entries(stats.methods || {}).sort((a, b) => b[1] - a[1]).slice(0, 6);
  }, [stats]);
  const blockedRate = useMemo(() => {
    if (!stats) {
      return 0;
    }
    const total = stats.allowed_requests + stats.blocked_requests;
    if (!total) {
      return 0;
    }
    return Math.round((stats.blocked_requests / total) * 100);
  }, [stats]);

  return (
    <div className="flex-1 bg-slate-900 global-scroll">
      <div className="p-8">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h2 className="text-3xl font-bold text-white mb-2">Audit Logs</h2>
            <p className="text-slate-400">Complete history of scans, admin actions, and live proxy events (auto-refresh every 3s)</p>
          </div>
          <button
            onClick={exportToExcel}
            disabled={filteredLogs.length === 0}
            className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-lg flex items-center gap-2 transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Download className="w-4 h-4" />
            Export Excel
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 mb-6">
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
            <div className="flex items-center gap-2 text-slate-400 text-sm mb-2">
              <Server className="w-4 h-4 text-cyan-400" />
              Proxy Status
            </div>
            <p className={`text-xl font-semibold ${health?.running ? 'text-emerald-300' : 'text-red-300'}`}>
              {health?.running ? 'Running' : 'Stopped'}
            </p>
            <p className="text-xs text-slate-500 mt-1">
              {health ? `${health.listen_host}:${health.listen_port} | uptime ${formatUptime(health.uptime_seconds)}` : 'No data'}
            </p>
          </div>

          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
            <div className="flex items-center gap-2 text-slate-400 text-sm mb-2">
              <Laptop className="w-4 h-4 text-cyan-400" />
              Connected Devices
            </div>
            <p className="text-xl font-semibold text-slate-100">{health?.connected_devices ?? devices.length}</p>
            <p className="text-xs text-slate-500 mt-1">Named automatically as PC 1, PC 2, ...</p>
          </div>

          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
            <div className="flex items-center gap-2 text-slate-400 text-sm mb-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Total Proxy Events
            </div>
            <p className="text-xl font-semibold text-slate-100">{stats?.total_events ?? health?.total_events ?? 0}</p>
            <p className="text-xs text-slate-500 mt-1">GET/POST on HTTP, CONNECT tunnels for HTTPS</p>
          </div>

          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
            <div className="flex items-center gap-2 text-slate-400 text-sm mb-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              Block Rate
            </div>
            <p className="text-xl font-semibold text-slate-100">{blockedRate}%</p>
            <p className="text-xs text-slate-500 mt-1">
              {stats ? `${stats.blocked_requests} blocked / ${stats.allowed_requests} allowed` : 'No data'}
            </p>
          </div>
        </div>

        {methodSummary.length > 0 && (
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4 mb-6">
            <p className="text-slate-300 text-sm mb-3">Traffic Methods Snapshot</p>
            <div className="flex flex-wrap gap-2">
              {methodSummary.map(([method, count]) => (
                <span key={method} className="px-3 py-1 rounded-full text-xs bg-slate-900/70 border border-slate-600 text-slate-200">
                  {method}: {count}
                </span>
              ))}
            </div>
          </div>
        )}

        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-white font-semibold">Connected Proxy Devices</h3>
            <p className="text-xs text-slate-500">Live updates every 3 seconds</p>
          </div>
          {devices.length === 0 ? (
            <p className="text-slate-400 text-sm">No devices seen yet. Connect another PC to your proxy to populate this list.</p>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
              {devices.map((d) => (
                <div key={d.client_ip} className="bg-slate-900/60 border border-slate-700 rounded-lg p-4">
                  <div className="flex items-center justify-between">
                    <p className="text-slate-100 font-semibold">{d.device_name}</p>
                    <span className="text-xs text-cyan-300">{d.client_ip}</span>
                  </div>
                  <div className="mt-2 text-xs text-slate-400 space-y-1">
                    <p>Total: {d.total_requests} | Blocked: {d.blocked_requests} | Allowed: {d.allowed_requests}</p>
                    <p>Last seen: {new Date(d.last_seen).toLocaleString()}</p>
                    <p>Last host: {d.last_host || '-'}</p>
                  </div>
                  <div className="flex flex-wrap gap-1 mt-3">
                    {Object.entries(d.methods || {}).map(([m, c]) => (
                      <span key={m} className="px-2 py-0.5 rounded-full text-[11px] bg-slate-800 border border-slate-600 text-slate-300">
                        {m} {c}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {gatewayError && (
          <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-4 mb-6">
            <p className="text-amber-300 text-sm">{gatewayError}</p>
          </div>
        )}

        {/* Filters Section */}
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 mb-6 space-y-4">
          <div className="flex items-center gap-2 mb-4">
            <Filter className="w-5 h-5 text-cyan-400" />
            <h3 className="text-white font-semibold">Filters & Search</h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search logs..."
                className="w-full pl-10 pr-4 py-2 bg-slate-900/50 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 text-sm"
              />
            </div>

            {/* Sort By */}
            <div className="relative">
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as 'date' | 'action' | 'user')}
                className="w-full px-4 py-2 bg-slate-900/50 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 appearance-none text-sm"
              >
                <option value="date">Sort by Date</option>
                <option value="action">Sort by Action</option>
                <option value="user">Sort by User</option>
              </select>
              <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
            </div>

            {/* Sort Order */}
            <div className="relative">
              <select
                value={sortOrder}
                onChange={(e) => setSortOrder(e.target.value as 'asc' | 'desc')}
                className="w-full px-4 py-2 bg-slate-900/50 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 appearance-none text-sm"
              >
                <option value="desc">Newest First</option>
                <option value="asc">Oldest First</option>
              </select>
              <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
            </div>

            {/* Action Filter */}
            <div className="relative">
              <select
                value={actionFilter}
                onChange={(e) => setActionFilter(e.target.value)}
                className="w-full px-4 py-2 bg-slate-900/50 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 appearance-none text-sm"
              >
                <option value="all">All Actions</option>
                {uniqueActions.map(action => (
                  <option key={action} value={action}>{action}</option>
                ))}
              </select>
              <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
            </div>
          </div>

          {/* Date Range */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-400 text-sm mb-2">Start Date</label>
              <input
                type="date"
                value={dateRange.start}
                onChange={(e) => setDateRange({ ...dateRange, start: e.target.value })}
                className="w-full px-4 py-2 bg-slate-900/50 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 text-sm"
              />
            </div>
            <div>
              <label className="block text-slate-400 text-sm mb-2">End Date</label>
              <input
                type="date"
                value={dateRange.end}
                onChange={(e) => setDateRange({ ...dateRange, end: e.target.value })}
                className="w-full px-4 py-2 bg-slate-900/50 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 text-sm"
              />
            </div>
          </div>

          {/* Clear Filters Button */}
          <div className="flex items-center justify-between pt-2">
            <p className="text-slate-400 text-sm">
              Showing {filteredLogs.length} of {logs.length} logs
            </p>
            <button
              onClick={clearFilters}
              className="px-4 py-2 text-slate-400 hover:text-white transition text-sm"
            >
              Clear Filters
            </button>
          </div>
        </div>

        {/* Logs Table */}
        <div className="max-w-7xl mx-auto">
          {loading && (
            <div className="text-center py-12">
              <div className="w-12 h-12 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
              <p className="text-slate-400">Loading logs...</p>
            </div>
          )}

          {error && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 mb-6">
              <p className="text-red-400">{error}</p>
            </div>
          )}

          {!loading && !error && filteredLogs.length === 0 && (
            <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-8 text-center">
              <FileText className="w-16 h-16 text-slate-600 mx-auto mb-4" />
              <p className="text-slate-400">
                {logs.length === 0 ? 'No audit logs found' : 'No logs match your filters'}
              </p>
            </div>
          )}

          {!loading && !error && filteredLogs.length > 0 && (
            <div className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-slate-900/50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                        Action
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                        Traffic
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                        Timestamp
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                        User
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                        Details
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700">
                    {filteredLogs.map((log) => (
                      <tr key={log.id} className="hover:bg-slate-900/30 transition">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                            {log.action}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          {(() => {
                            const t = parseTrafficMeta(log);
                            if (!t.isGateway) {
                              return <span className="text-slate-500 text-xs">-</span>;
                            }
                            return (
                              <div className="flex items-center gap-1">
                                <span className="px-2 py-0.5 rounded-full text-[11px] bg-blue-500/15 border border-blue-500/30 text-blue-300">{t.protocol}</span>
                                <span className="px-2 py-0.5 rounded-full text-[11px] bg-slate-700 border border-slate-600 text-slate-200">{t.method}</span>
                                <span className={`px-2 py-0.5 rounded-full text-[11px] border ${t.verdict === 'BLOCK' ? 'bg-red-500/15 border-red-500/30 text-red-300' : 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'}`}>
                                  {t.verdict}
                                </span>
                              </div>
                            );
                          })()}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center gap-2 text-slate-300">
                            <Calendar className="w-4 h-4 text-slate-500" />
                            {new Date(log.timestamp).toLocaleString()}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center gap-2 text-slate-300">
                            <User className="w-4 h-4 text-slate-500" />
                            <div className="leading-tight">
                              <p className="text-slate-200">{log.user_name || (log.user_id === null ? 'System' : `User #${log.user_id}`)}</p>
                              {log.user_email && (
                                <p className="text-slate-500 text-xs">{log.user_email}</p>
                              )}
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4 text-slate-300 max-w-md truncate">
                          {log.details}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
