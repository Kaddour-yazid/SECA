import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Briefcase,
  CheckCircle,
  Clock3,
  Network,
  Shield,
  Users,
  Wifi,
  XCircle,
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { apiUrl } from '../config/api';

type EmployeeUsage = {
  name: string;
  team: string;
  totalSearches: number;
  risk: 'low' | 'medium' | 'high';
};

type DeviceStatus = {
  hostname: string;
  ip: string;
  state: 'online' | 'warning' | 'offline';
  lastSync: string;
};

type ScanRow = {
  id: number;
  scan_type: string;
  target: string;
  status: string;
  created_at: string;
};

type SiteStat = {
  domain: string;
  label: string;
  hits: number;
  percent: number;
  color: string;
  iconUrl: string;
};

type TrafficEvent = {
  mode: 'Blocked' | 'Monitored' | 'Allowed';
  domain: string;
  source: string;
  timeLabel: string;
};

const mockEmployees: EmployeeUsage[] = [
  { name: 'Nora A.', team: 'Support', totalSearches: 116, risk: 'high' },
  { name: 'Khaled M.', team: 'Sales', totalSearches: 84, risk: 'medium' },
  { name: 'Imane T.', team: 'HR', totalSearches: 52, risk: 'low' },
  { name: 'Yassine B.', team: 'Finance', totalSearches: 73, risk: 'medium' },
];

const mockDevices: DeviceStatus[] = [
  { hostname: 'PC-ACCOUNTING-03', ip: '10.10.4.28', state: 'online', lastSync: '8s ago' },
  { hostname: 'PC-SALES-11', ip: '10.10.5.77', state: 'warning', lastSync: '44s ago' },
  { hostname: 'PC-SUPPORT-02', ip: '10.10.6.15', state: 'online', lastSync: '3s ago' },
  { hostname: 'PC-LOBBY-01', ip: '10.10.9.12', state: 'offline', lastSync: '9m ago' },
];

const mockPolicies = [
  { category: 'Streaming and Entertainment', mode: 'Blocked', matches: 74, active: true },
  { category: 'AI Assistants', mode: 'Monitored', matches: 183, active: true },
  { category: 'Social Media', mode: 'Blocked', matches: 41, active: true },
  { category: 'Professional Platforms', mode: 'Allowed', matches: 129, active: true },
  { category: 'Unknown Domains', mode: 'Challenge', matches: 16, active: true },
];

const palette = ['#06b6d4', '#ef4444', '#3b82f6', '#22c55e', '#f59e0b'];

const riskBadge = (risk: EmployeeUsage['risk']) =>
  risk === 'high'
    ? 'text-red-400 bg-red-500/10 border-red-500/30'
    : risk === 'medium'
    ? 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30'
    : 'text-green-400 bg-green-500/10 border-green-500/30';

const deviceIcon = (state: DeviceStatus['state']) =>
  state === 'online' ? (
    <CheckCircle className="w-4 h-4 text-green-400" />
  ) : state === 'warning' ? (
    <AlertTriangle className="w-4 h-4 text-yellow-400" />
  ) : (
    <XCircle className="w-4 h-4 text-red-400" />
  );

const normalizeDomain = (value: string): string | null => {
  if (!value) return null;
  const raw = value.trim();

  try {
    const withScheme = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
    const host = new URL(withScheme).hostname.toLowerCase().replace(/^www\./, '');
    return host || null;
  } catch {
    return null;
  }
};

const domainToLabel = (domain: string): string => {
  const first = domain.split('.')[0] || domain;
  return first.charAt(0).toUpperCase() + first.slice(1);
};

const faviconUrl = (domain: string): string =>
  `https://www.google.com/s2/favicons?domain=${encodeURIComponent(domain)}&sz=64`;

const percentageBreakdown = (weights: number[]): number[] => {
  const total = weights.reduce((sum, v) => sum + v, 0) || 1;
  return weights.map((w) => Math.round((w / total) * 100));
};

const ringStyle = (color: string, percent: number) => ({
  background: `conic-gradient(${color} ${Math.min(100, Math.max(0, percent)) * 3.6}deg, #1e293b 0deg)`,
});

export function GatewayStartView() {
  const { token } = useAuth();
  const [activePanel, setActivePanel] = useState<'overview' | 'employees' | 'policies'>('overview');
  const [scanRows, setScanRows] = useState<ScanRow[]>([]);

  useEffect(() => {
    if (!token) return;

    const loadScanRows = async () => {
      try {
        const res = await fetch(apiUrl('/scans?limit=500'), {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) return;
        const data: ScanRow[] = await res.json();
        setScanRows(Array.isArray(data) ? data : []);
      } catch {
        // Design page should keep working even when API is unavailable.
      }
    };

    void loadScanRows();
  }, [token]);

  const topSites = useMemo<SiteStat[]>(() => {
    const domainHits = new Map<string, number>();

    for (const scan of scanRows) {
      if (!scan.target) continue;
      if (!scan.scan_type?.toLowerCase().includes('url')) continue;

      const domain = normalizeDomain(scan.target);
      if (!domain) continue;
      domainHits.set(domain, (domainHits.get(domain) || 0) + 1);
    }

    let entries = Array.from(domainHits.entries()).sort((a, b) => b[1] - a[1]).slice(0, 6);

    if (!entries.length) {
      entries = [
        ['chatgpt.com', 46],
        ['youtube.com', 24],
        ['linkedin.com', 14],
        ['github.com', 10],
        ['facebook.com', 4],
        ['wikipedia.org', 2],
      ];
    }

    const total = entries.reduce((sum, [, hits]) => sum + hits, 0) || 1;

    return entries.map(([domain, hits], idx) => ({
      domain,
      label: domainToLabel(domain),
      hits,
      percent: Math.round((hits / total) * 100),
      color: palette[idx % palette.length],
      iconUrl: faviconUrl(domain),
    }));
  }, [scanRows]);

  const employeeSiteUsage = useMemo(() => {
    return mockEmployees.map((employee, employeeIndex) => {
      const baseSeed = employee.name.split('').reduce((sum, ch) => sum + ch.charCodeAt(0), 0);
      const weights = topSites.map((site, siteIndex) => {
        const base = (baseSeed * (siteIndex + 3)) % 37;
        const riskBoost = employee.risk === 'high' && siteIndex === 0 ? 15 : employee.risk === 'medium' && siteIndex === 0 ? 7 : 0;
        return Math.max(10, base + riskBoost + (site.percent / 5) + employeeIndex * 2);
      });

      const percents = percentageBreakdown(weights);

      const sites = topSites.map((site, idx) => ({
        ...site,
        percent: percents[idx] ?? 0,
      }));

      const nonWorkPercent = sites
        .filter((s) => /(youtube|facebook|instagram|tiktok|netflix|x\.com)/i.test(s.domain))
        .reduce((sum, s) => sum + s.percent, 0);

      return { employee, sites, nonWorkPercent };
    });
  }, [topSites]);

  const liveTraffic = useMemo<TrafficEvent[]>(() => {
    const usable = scanRows
      .filter((row) => row.scan_type?.toLowerCase().includes('url') && !!normalizeDomain(row.target))
      .slice(0, 8);

    if (usable.length) {
      return usable.map((row, idx) => {
        const domain = normalizeDomain(row.target) || 'unknown.local';
        const mode: TrafficEvent['mode'] =
          row.status === 'malicious' ? 'Blocked' : row.status === 'suspicious' ? 'Monitored' : 'Allowed';
        const time = row.created_at ? new Date(row.created_at) : new Date();
        return {
          mode,
          domain,
          source: mockDevices[idx % mockDevices.length].hostname,
          timeLabel: time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        };
      });
    }

    return [
      { mode: 'Blocked', domain: 'youtube.com', source: 'PC-SALES-11', timeLabel: '14:10' },
      { mode: 'Monitored', domain: 'chatgpt.com', source: 'PC-ACCOUNTING-03', timeLabel: '14:08' },
      { mode: 'Allowed', domain: 'linkedin.com', source: 'PC-HR-04', timeLabel: '14:02' },
      { mode: 'Blocked', domain: 'facebook.com', source: 'PC-SUPPORT-02', timeLabel: '13:57' },
    ];
  }, [scanRows]);

  const stats = useMemo(() => {
    const totalQueries = scanRows.filter((row) => !!normalizeDomain(row.target)).length || mockEmployees.reduce((sum, e) => sum + e.totalSearches, 0);
    const highRiskUsers = employeeSiteUsage.filter((entry) => entry.employee.risk === 'high').length;
    const onlineGateways = mockDevices.filter((d) => d.state === 'online').length;
    const policyHits = scanRows.filter((row) => row.status === 'malicious' || row.status === 'suspicious').length || mockPolicies.reduce((sum, p) => sum + p.matches, 0);
    return { totalQueries, highRiskUsers, onlineGateways, policyHits };
  }, [scanRows, employeeSiteUsage]);

  const onlinePercent = Math.round((stats.onlineGateways / mockDevices.length) * 100);

  return (
    <div className="gateway-start flex-1 bg-slate-900 global-scroll">
      <div className="p-8 space-y-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-3xl font-bold text-white mb-2">Monitoring</h2>
            <p className="text-slate-400">Design preview for employee web-usage gateway monitoring and policy control.</p>
          </div>
          <div className="px-3 py-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-300 text-sm">
            UI Mock + Real Scan Flavor
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <p className="text-slate-400 text-sm">Active Gateways</p>
              <Network className="w-5 h-5 text-cyan-400" />
            </div>
            <p className="text-3xl font-bold text-white">{stats.onlineGateways}/{mockDevices.length}</p>
          </div>
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <p className="text-slate-400 text-sm">Tracked Searches</p>
              <BarChart3 className="w-5 h-5 text-cyan-400" />
            </div>
            <p className="text-3xl font-bold text-white">{stats.totalQueries}</p>
          </div>
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <p className="text-slate-400 text-sm">Policy Hits</p>
              <Shield className="w-5 h-5 text-cyan-400" />
            </div>
            <p className="text-3xl font-bold text-white">{stats.policyHits}</p>
          </div>
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <p className="text-slate-400 text-sm">High-Risk Users</p>
              <AlertTriangle className="w-5 h-5 text-red-400" />
            </div>
            <p className="text-3xl font-bold text-red-400">{stats.highRiskUsers}</p>
          </div>
        </div>

        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-2 flex gap-2">
          {[
            { id: 'overview', label: 'Overview', icon: Activity },
            { id: 'employees', label: 'Employees', icon: Users },
            { id: 'policies', label: 'Policies', icon: Briefcase },
          ].map((tab) => {
            const Icon = tab.icon;
            const active = activePanel === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActivePanel(tab.id as 'overview' | 'employees' | 'policies')}
                className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg transition ${
                  active
                    ? 'bg-cyan-500 text-white shadow-lg'
                    : 'text-slate-300 hover:bg-cyan-500/10 hover:text-cyan-400'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span className="font-medium">{tab.label}</span>
              </button>
            );
          })}
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          <div className="xl:col-span-2 bg-slate-800/50 border border-slate-700 rounded-xl p-6">
            <h3 className="text-xl font-bold text-white mb-4">
              {activePanel === 'overview' && 'Employee Search Distribution'}
              {activePanel === 'employees' && 'Employee Behavior Breakdown'}
              {activePanel === 'policies' && 'Policy Builder Preview'}
            </h3>

            {(activePanel === 'overview' || activePanel === 'employees') && (
              <>
                <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-4 mb-4">
                  <div className="flex items-center justify-between mb-3">
                    <p className="text-slate-200 text-sm font-semibold">Top websites from URL scan data</p>
                    <span className="text-xs text-slate-400">{topSites.reduce((sum, site) => sum + site.hits, 0)} tracked hits</span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {topSites.map((site) => (
                      <div key={site.domain} className="gateway-stat-item rounded-lg border border-slate-700 bg-slate-800/70 p-3">
                        <div className="flex items-center justify-between gap-2 mb-2">
                          <div className="flex items-center gap-2 min-w-0">
                            <img src={site.iconUrl} alt={site.label} className="w-5 h-5 rounded" />
                            <span className="text-slate-100 text-sm font-medium truncate">{site.domain}</span>
                          </div>
                          <span className="text-cyan-300 text-xs font-semibold">{site.percent}%</span>
                        </div>
                        <div className="w-full h-2 rounded-full bg-slate-900 border border-slate-700 overflow-hidden">
                          <div className="h-full rounded-full" style={{ width: `${site.percent}%`, backgroundColor: site.color }} />
                        </div>
                        <p className="text-slate-400 text-xs mt-2">{site.hits} scans</p>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="space-y-4">
                  {employeeSiteUsage.map(({ employee, sites, nonWorkPercent }) => (
                    <div key={employee.name} className="gateway-employee-card bg-slate-900/50 border border-slate-700 rounded-lg p-4">
                      <div className="flex items-start justify-between mb-4">
                        <div>
                          <p className="text-white font-semibold text-lg">{employee.name}</p>
                          <p className="text-slate-400 text-sm">{employee.team} - {employee.totalSearches} searches</p>
                        </div>
                        <div className="text-right">
                          <span className={`px-2 py-1 text-xs rounded-full border ${riskBadge(employee.risk)}`}>
                            {employee.risk.toUpperCase()} RISK
                          </span>
                          <p className="text-slate-400 text-xs mt-2">Non-work trend: {nonWorkPercent}%</p>
                        </div>
                      </div>

                      <div className="flex flex-wrap gap-5">
                        {sites.map((site) => (
                          <div key={`${employee.name}-${site.domain}`} className="min-w-[96px] text-center">
                            <div className="relative w-16 h-16 mx-auto rounded-full p-[4px]" style={ringStyle(site.color, site.percent)}>
                              <div className="w-full h-full rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center">
                                <img src={site.iconUrl} alt={site.label} className="w-8 h-8 rounded" />
                              </div>
                            </div>
                            <p className="text-slate-200 text-sm mt-2 font-medium">{site.label}</p>
                            <p className="text-slate-400 text-xs">{site.percent}%</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}

            {activePanel === 'policies' && (
              <div className="space-y-3">
                {mockPolicies.map((policy) => (
                  <div key={policy.category} className="bg-slate-900/50 border border-slate-700 rounded-lg p-4 flex items-center justify-between">
                    <div>
                      <p className="text-white font-medium">{policy.category}</p>
                      <p className="text-slate-400 text-sm">Mode: {policy.mode} - {policy.matches} matches this week</p>
                    </div>
                    <div className={`px-3 py-1 rounded-full text-xs border ${
                      policy.mode === 'Blocked'
                        ? 'text-red-400 bg-red-500/10 border-red-500/30'
                        : policy.mode === 'Monitored'
                        ? 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30'
                        : 'text-green-400 bg-green-500/10 border-green-500/30'
                    }`}>
                      {policy.active ? 'ACTIVE' : 'DISABLED'}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="space-y-6">
            <div className="gateway-status-card bg-gradient-to-br from-cyan-500/20 via-blue-500/10 to-slate-900/60 border border-cyan-400/30 rounded-2xl p-6 shadow-[0_0_40px_rgba(6,182,212,0.12)]">
              <div className="flex items-center justify-between mb-4">
                <h4 className="text-white font-semibold flex items-center gap-2 text-lg">
                  <Wifi className="w-5 h-5 text-cyan-300" />
                  Gateway Device Status
                </h4>
                <span className="text-cyan-200 text-xs border border-cyan-400/30 bg-cyan-500/10 px-3 py-1 rounded-full">Real-time</span>
              </div>

              <div className="grid grid-cols-[1fr_auto] gap-4 items-end mb-5">
                <div>
                  <p className="text-slate-300 text-sm mb-1">Gateway Health Index</p>
                  <p className="text-7xl font-black tracking-tight text-white leading-none">{onlinePercent}%</p>
                  <p className="text-slate-300 text-base mt-2">{stats.onlineGateways} of {mockDevices.length} endpoints operational</p>
                </div>
                <div className="w-20 h-20 rounded-2xl bg-cyan-500/15 border border-cyan-400/30 flex items-center justify-center">
                  <Network className="w-10 h-10 text-cyan-300" />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-2 mb-5">
                <div className="gateway-mini-stat bg-slate-900/70 border border-slate-700 rounded-lg p-3 text-center">
                  <p className="text-xs text-slate-400">Online</p>
                  <p className="text-2xl font-extrabold text-green-400">{mockDevices.filter((d) => d.state === 'online').length}</p>
                </div>
                <div className="gateway-mini-stat bg-slate-900/70 border border-slate-700 rounded-lg p-3 text-center">
                  <p className="text-xs text-slate-400">Warning</p>
                  <p className="text-2xl font-extrabold text-yellow-400">{mockDevices.filter((d) => d.state === 'warning').length}</p>
                </div>
                <div className="gateway-mini-stat bg-slate-900/70 border border-slate-700 rounded-lg p-3 text-center">
                  <p className="text-xs text-slate-400">Offline</p>
                  <p className="text-2xl font-extrabold text-red-400">{mockDevices.filter((d) => d.state === 'offline').length}</p>
                </div>
              </div>

              <div className="space-y-2">
                {mockDevices.map((device) => (
                  <div key={device.hostname} className="gateway-device-row bg-slate-900/70 border border-slate-700 rounded-lg p-3">
                    <div className="flex items-center justify-between">
                      <p className="text-slate-100 font-semibold text-sm">{device.hostname}</p>
                      {deviceIcon(device.state)}
                    </div>
                    <p className="text-slate-400 text-xs mt-1">{device.ip} - last sync {device.lastSync}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="gateway-traffic-card bg-slate-800/60 border border-slate-700 rounded-2xl p-5">
              <div className="flex items-center justify-between mb-4">
                <h4 className="text-white font-semibold flex items-center gap-2 text-lg">
                  <Activity className="w-5 h-5 text-cyan-300" />
                  Live Traffic Snapshot
                </h4>
                <span className="text-slate-400 text-xs">{liveTraffic.length} recent events</span>
              </div>

              <div className="space-y-3">
                {liveTraffic.map((event, idx) => (
                  <div key={`${event.domain}-${idx}`} className="gateway-traffic-row bg-slate-900/60 border border-slate-700 rounded-xl p-3">
                    <div className="flex items-center justify-between gap-2 mb-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <img src={faviconUrl(event.domain)} alt={event.domain} className="w-6 h-6 rounded" />
                        <p className="text-slate-100 text-base font-semibold truncate">{event.domain}</p>
                      </div>
                      <span className={`px-2.5 py-1 rounded-full text-xs border font-semibold ${
                        event.mode === 'Blocked'
                          ? 'text-red-400 bg-red-500/10 border-red-500/30'
                          : event.mode === 'Monitored'
                          ? 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30'
                          : 'text-green-400 bg-green-500/10 border-green-500/30'
                      }`}>
                        {event.mode}
                      </span>
                    </div>

                    <div className="flex items-center justify-between text-sm text-slate-400">
                      <span>{event.source}</span>
                      <span className="inline-flex items-center gap-1"><Clock3 className="w-3.5 h-3.5" />{event.timeLabel}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
