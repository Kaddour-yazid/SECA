import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  BarChart3,
  Briefcase,
  Clock3,
  Globe,
  Shield,
  UserCheck,
  UserPlus,
  Users,
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useLanguage } from '../contexts/LanguageContext';
import { apiUrl } from '../config/api';

type MonitoringTab = 'overview' | 'employees' | 'sessions' | 'person-detail' | 'group-detail';
type MonitoringRange = 'day' | '3days' | 'week' | 'month';

type UserRow = {
  id: number;
  email: string;
  first_name?: string | null;
  last_name?: string | null;
  sex?: string | null;
  department?: string | null;
  group_name?: string | null;
  role?: string | null;
  is_admin: boolean;
  admin_department?: boolean;
  admin_group?: boolean;
  created_at: string;
};

type ScanRow = {
  id: number;
  user_id?: number | null;
  scan_type: string;
  target: string;
  status: string;
  created_at: string;
};

type DesktopSessionRow = {
  session_id: string;
  user_id: number;
  user_name: string;
  email: string;
  department?: string | null;
  group_name?: string | null;
  role?: string | null;
  is_admin: boolean;
  device_id?: string | null;
  hostname?: string | null;
  platform?: string | null;
  app_version?: string | null;
  proxy_host?: string | null;
  proxy_port?: number | null;
  assigned_proxy_host?: string | null;
  assigned_proxy_port?: number | null;
  proxy_state?: string | null;
  started_at?: string | null;
  last_heartbeat?: string | null;
  online: boolean;
  disconnect_reason?: string | null;
  seconds_since_last_heartbeat?: number | null;
};

type GatewayHistoryRow = {
  timestamp?: string | null;
  host?: string | null;
  port?: number | null;
  method?: string | null;
  blocked?: boolean;
  block_reason?: string | null;
  user_name?: string | null;
  user_email?: string | null;
  department?: string | null;
  group_name?: string | null;
  hostname?: string | null;
};

type GroupProxyAssignment = {
  department: string;
  group_name: string;
  scope?: string | null;
  proxy_host: string;
  proxy_port: number;
  enabled: boolean;
  note?: string | null;
};

type ProxyUsageSiteRow = {
  host: string;
  request_count: number;
  blocked_count?: number;
  allowed_count?: number;
  clean_count?: number;
  suspicious_count?: number;
  malicious_count?: number;
  unique_members?: number;
  last_seen?: string | null;
};

type ProxyUsageMemberRow = {
  user_id: number | null;
  email?: string | null;
  name: string;
  request_count: number;
  blocked_count: number;
  allowed_count: number;
  unique_sites: number;
  last_seen?: string | null;
  top_sites: ProxyUsageSiteRow[];
};

type ProxyUsageGroupRow = {
  group_name: string;
  department: string;
  request_count: number;
  blocked_count: number;
  allowed_count: number;
  unique_sites: number;
  unique_members: number;
  last_seen?: string | null;
  top_sites: ProxyUsageSiteRow[];
};

type ProxyUsageDailyRow = {
  date: string;
  request_count: number;
  blocked_count: number;
  allowed_count: number;
  unique_sites: number;
  unique_members: number;
};

type ProxyUsageSummary = {
  department: string;
  group_name?: string | null;
  scope?: string | null;
  request_count: number;
  blocked_count: number;
  allowed_count: number;
  unique_sites: number;
  unique_members: number;
};

type ProxyUsageStatsPayload = {
  period: MonitoringRange;
  days: number;
  generated_at: string;
  group_summary: ProxyUsageSummary;
  top_sites: ProxyUsageSiteRow[];
  member_stats: ProxyUsageMemberRow[];
  group_stats: ProxyUsageGroupRow[];
  daily_stats: ProxyUsageDailyRow[];
};

type EmployeeSlot = {
  key: string;
  id: number | null;
  name: string;
  email: string | null;
  sex: string | null;
  department: string;
  group_name: string;
  joinedAt: string | null;
  state: 'registered' | 'placeholder';
};

const EXPECTED_GROUP_EMPLOYEES = 3;

const isDepartmentAdminUser = (user?: { is_admin?: boolean; admin_department?: boolean } | null) =>
  Boolean(user?.is_admin && user?.admin_department);

const formatName = (user: UserRow) => {
  const first = (user.first_name || '').trim();
  const last = (user.last_name || '').trim();
  const combined = `${first} ${last}`.trim();
  return combined || user.email;
};

const formatDate = (value: string | null) => {
  if (!value) return 'Pending';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Pending';
  return date.toLocaleDateString();
};

const formatDateTime = (value: string | null) => {
  if (!value) return 'No activity yet';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'No activity yet';
  return date.toLocaleString();
};

const KNOWN_SITE_RULES: Array<{ suffixes: string[]; label: string; iconHost?: string }> = [
  { suffixes: ['youtube.com', 'youtu.be'], label: 'YouTube', iconHost: 'youtube.com' },
  { suffixes: ['play.google.com'], label: 'Google Play', iconHost: 'play.google.com' },
  { suffixes: ['google.com', 'gstatic.com', 'googleapis.com', 'clients6.google.com'], label: 'Google', iconHost: 'google.com' },
  { suffixes: ['facebook.com', 'fbcdn.net'], label: 'Facebook', iconHost: 'facebook.com' },
  { suffixes: ['instagram.com', 'cdninstagram.com'], label: 'Instagram', iconHost: 'instagram.com' },
  { suffixes: ['whatsapp.com', 'whatsapp.net'], label: 'WhatsApp', iconHost: 'whatsapp.com' },
  { suffixes: ['x.com', 'twitter.com', 't.co'], label: 'X', iconHost: 'x.com' },
  { suffixes: ['tiktok.com'], label: 'TikTok', iconHost: 'tiktok.com' },
  { suffixes: ['linkedin.com'], label: 'LinkedIn', iconHost: 'linkedin.com' },
  { suffixes: ['github.com', 'githubusercontent.com'], label: 'GitHub', iconHost: 'github.com' },
  { suffixes: ['microsoft.com', 'live.com', 'outlook.com', 'office.com'], label: 'Microsoft', iconHost: 'microsoft.com' },
  { suffixes: ['openai.com', 'chatgpt.com'], label: 'OpenAI', iconHost: 'openai.com' },
  { suffixes: ['wikipedia.org'], label: 'Wikipedia', iconHost: 'wikipedia.org' },
  { suffixes: ['netflix.com'], label: 'Netflix', iconHost: 'netflix.com' },
  { suffixes: ['amazon.com', 'amazonaws.com'], label: 'Amazon', iconHost: 'amazon.com' },
  { suffixes: ['discord.com', 'discord.gg'], label: 'Discord', iconHost: 'discord.com' },
  { suffixes: ['spotify.com', 'scdn.co'], label: 'Spotify', iconHost: 'spotify.com' },
];

const looksLikeIPv4 = (value: string) => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value.trim());

const titleCaseToken = (value: string) =>
  value
    .split(/[-_]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');

const humanizeUnknownHost = (host: string) => {
  const normalized = host.trim().toLowerCase().replace(/^www\./, '');
  if (!normalized) return 'Unknown Site';
  if (looksLikeIPv4(normalized)) return normalized;
  const parts = normalized.split('.').filter(Boolean);
  if (!parts.length) return normalized;
  if (parts.length >= 2) {
    const registrable = parts[0];
    return titleCaseToken(registrable);
  }
  return titleCaseToken(parts[0]);
};

const resolveSitePresentation = (host?: string | null) => {
  const rawHost = (host || '').trim().toLowerCase();
  if (!rawHost) {
    return {
      label: 'Unknown Site',
      faviconHost: null as string | null,
      secondary: null as string | null,
      rawHost: '',
    };
  }

  const normalized = rawHost.replace(/^www\./, '');
  const matchedRule = KNOWN_SITE_RULES.find((rule) =>
    rule.suffixes.some((suffix) => normalized === suffix || normalized.endsWith(`.${suffix}`)),
  );

  if (matchedRule) {
    return {
      label: matchedRule.label,
      faviconHost: matchedRule.iconHost || matchedRule.suffixes[0],
      secondary: normalized !== (matchedRule.iconHost || matchedRule.suffixes[0]) ? normalized : null,
      rawHost,
    };
  }

  if (looksLikeIPv4(normalized)) {
    return {
      label: normalized,
      faviconHost: null,
      secondary: null,
      rawHost,
    };
  }

  return {
    label: humanizeUnknownHost(normalized),
    faviconHost: normalized,
    secondary: normalized,
    rawHost,
  };
};

function SiteIdentity({
  host,
  compact = false,
  showSecondary = true,
}: {
  host?: string | null;
  compact?: boolean;
  showSecondary?: boolean;
}) {
  const [iconFailed, setIconFailed] = useState(false);
  const site = resolveSitePresentation(host);
  const faviconUrl = site.faviconHost
    ? `https://www.google.com/s2/favicons?domain=${encodeURIComponent(site.faviconHost)}&sz=64`
    : null;

  return (
    <div className="flex min-w-0 items-center gap-3">
      <div className={`flex shrink-0 items-center justify-center rounded-full border border-slate-700 bg-slate-900/70 ${compact ? 'h-8 w-8' : 'h-10 w-10'}`}>
        {faviconUrl && !iconFailed ? (
          <img
            src={faviconUrl}
            alt={site.label}
            className={compact ? 'h-4 w-4 rounded-sm' : 'h-5 w-5 rounded-sm'}
            loading="lazy"
            onError={() => setIconFailed(true)}
          />
        ) : (
          <Globe className={compact ? 'h-4 w-4 text-cyan-300' : 'h-5 w-5 text-cyan-300'} />
        )}
      </div>
      <div className="min-w-0">
        <p className={`truncate font-semibold text-white ${compact ? 'text-sm' : 'text-sm'}`}>{site.label}</p>
        {showSecondary && site.secondary ? (
          <p className="truncate text-xs text-slate-500">{site.secondary}</p>
        ) : null}
      </div>
    </div>
  );
}

function SiteStatusBadges({ site }: { site: ProxyUsageSiteRow }) {
  return (
    <div className="mt-3 flex flex-wrap gap-2 text-xs">
      {typeof site.allowed_count === 'number' ? (
        <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-emerald-300">
          Allowed {site.allowed_count}
        </span>
      ) : null}
      {typeof site.blocked_count === 'number' ? (
        <span className="rounded-full border border-red-500/30 bg-red-500/10 px-2.5 py-1 text-red-300">
          Blocked {site.blocked_count}
        </span>
      ) : null}
      {typeof site.clean_count === 'number' && site.clean_count > 0 ? (
        <span
          title="Number of proxy requests for this site classified as clean in the selected window."
          className="rounded-full border border-cyan-500/30 bg-cyan-500/10 px-2.5 py-1 text-cyan-300"
        >
          Clean {site.clean_count}
        </span>
      ) : null}
      {typeof site.suspicious_count === 'number' && site.suspicious_count > 0 ? (
        <span
          title="Number of proxy requests for this site classified as suspicious in the selected window."
          className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-amber-300"
        >
          Suspicious {site.suspicious_count}
        </span>
      ) : null}
      {typeof site.malicious_count === 'number' && site.malicious_count > 0 ? (
        <span
          title="Number of proxy requests for this site classified as malicious in the selected window."
          className="rounded-full border border-rose-500/30 bg-rose-500/10 px-2.5 py-1 text-rose-300"
        >
          Malicious {site.malicious_count}
        </span>
      ) : null}
    </div>
  );
}

const formatProxyEndpoint = (host?: string | null, port?: number | null) => {
  const normalizedHost = (host || '').trim();
  if (!normalizedHost) return 'Not detected';
  return port ? `${normalizedHost}:${port}` : normalizedHost;
};

const proxyStateMeta = (state?: string | null) => {
  switch (state) {
    case 'ok':
      return {
        label: 'Proxy OK',
        className: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
      };
    case 'disabled':
      return {
        label: 'Proxy Disabled',
        className: 'border-red-500/30 bg-red-500/10 text-red-300',
      };
    case 'mismatch':
      return {
        label: 'Proxy Mismatch',
        className: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
      };
    case 'browser-unavailable':
      return {
        label: 'Browser Mode',
        className: 'border-sky-500/30 bg-sky-500/10 text-sky-300',
      };
    case 'offline':
      return {
        label: 'Offline',
        className: 'border-slate-700 bg-slate-800/70 text-slate-300',
      };
    default:
      return {
        label: 'No Assignment',
        className: 'border-slate-700 bg-slate-800/70 text-slate-300',
      };
  }
};

const isProxyConnected = (session?: DesktopSessionRow) =>
  Boolean(session?.online && session?.proxy_state === 'ok');

const connectionSummary = (session?: DesktopSessionRow) => {
  if (!session) {
    return {
      label: 'No session yet',
      tone: 'text-slate-500',
      badge: 'Registered',
      badgeClass: 'border-slate-700 bg-slate-800/70 text-slate-300',
    };
  }

  if (!session.online) {
    return {
      label: `Last heartbeat ${formatDateTime(session.last_heartbeat || null)}`,
      tone: 'text-slate-500',
      badge: 'Offline',
      badgeClass: 'border-slate-700 bg-slate-800/70 text-slate-300',
    };
  }

  if (session.proxy_state === 'ok') {
    return {
      label: `Proxy connected from ${session.hostname || session.device_id || 'desktop'}`,
      tone: 'text-emerald-300',
      badge: 'Proxy Connected',
      badgeClass: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
    };
  }

  if (session.proxy_state === 'browser-unavailable') {
    return {
      label: 'Browser session active, proxy state unavailable',
      tone: 'text-sky-300',
      badge: 'Browser Session',
      badgeClass: 'border-sky-500/30 bg-sky-500/10 text-sky-300',
    };
  }

  return {
    label: 'Session active, but proxy is disabled or mismatched',
    tone: 'text-amber-300',
    badge: 'Proxy Off',
    badgeClass: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
  };
};

export function GatewayStartView() {
  const { token, user } = useAuth();
  const { translateText } = useLanguage();
  const [activePanel, setActivePanel] = useState<MonitoringTab>('overview');
  const [activeRange, setActiveRange] = useState<MonitoringRange>('week');
  const [users, setUsers] = useState<UserRow[]>([]);
  const [scanRows, setScanRows] = useState<ScanRow[]>([]);
  const [desktopSessions, setDesktopSessions] = useState<DesktopSessionRow[]>([]);
  const [gatewayHistory, setGatewayHistory] = useState<GatewayHistoryRow[]>([]);
  const [groupProxyAssignment, setGroupProxyAssignment] = useState<GroupProxyAssignment | null>(null);
  const [proxyUsageStats, setProxyUsageStats] = useState<ProxyUsageStatsPayload | null>(null);
  const [selectedMemberId, setSelectedMemberId] = useState<number | null>(null);
  const [selectedGroupName, setSelectedGroupName] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!token) return;

    const loadMonitoringData = async () => {
      setLoading(true);
      try {
        const [usersRes, scansRes, sessionsRes, historyRes, assignmentRes, usageStatsRes] = await Promise.all([
          fetch(apiUrl('/users'), {
            headers: { Authorization: `Bearer ${token}` },
          }),
          fetch(apiUrl('/scans?limit=500'), {
            headers: { Authorization: `Bearer ${token}` },
          }),
          fetch(apiUrl('/monitoring/desktop/sessions'), {
            headers: { Authorization: `Bearer ${token}` },
          }),
          fetch(apiUrl('/gateway/api/history?limit=25'), {
            headers: { Authorization: `Bearer ${token}` },
          }),
          fetch(apiUrl('/monitoring/group-proxy-assignment'), {
            headers: { Authorization: `Bearer ${token}` },
          }),
          fetch(apiUrl(`/monitoring/proxy-usage-stats?period=${activeRange}`), {
            headers: { Authorization: `Bearer ${token}` },
          }),
        ]);

        if (usersRes.ok) {
          const userData: UserRow[] = await usersRes.json();
          setUsers(Array.isArray(userData) ? userData : []);
        } else {
          setUsers([]);
        }

        if (scansRes.ok) {
          const scanData: ScanRow[] = await scansRes.json();
          setScanRows(Array.isArray(scanData) ? scanData : []);
        } else {
          setScanRows([]);
        }

        if (sessionsRes.ok) {
          const sessionData = await sessionsRes.json();
          const rows = Array.isArray(sessionData?.sessions) ? sessionData.sessions : [];
          setDesktopSessions(rows as DesktopSessionRow[]);
        } else {
          setDesktopSessions([]);
        }

        if (historyRes.ok) {
          const historyData: GatewayHistoryRow[] = await historyRes.json();
          setGatewayHistory(Array.isArray(historyData) ? historyData : []);
        } else {
          setGatewayHistory([]);
        }

        if (assignmentRes.ok) {
          const assignmentData = await assignmentRes.json();
          setGroupProxyAssignment(assignmentData?.assignment ?? null);
        } else {
          setGroupProxyAssignment(null);
        }

        if (usageStatsRes.ok) {
          const usageData = await usageStatsRes.json();
          setProxyUsageStats(usageData as ProxyUsageStatsPayload);
        } else {
          setProxyUsageStats(null);
        }
      } catch {
        setUsers([]);
        setScanRows([]);
        setDesktopSessions([]);
        setGatewayHistory([]);
        setGroupProxyAssignment(null);
        setProxyUsageStats(null);
      } finally {
        setLoading(false);
      }
    };

    void loadMonitoringData();
    const intervalId = window.setInterval(() => {
      void loadMonitoringData();
    }, 10000);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [token, activeRange]);

  const adminDepartment = user?.department || '';
  const adminGroup = user?.group_name || '';
  const departmentAdmin = isDepartmentAdminUser(user);
  const scopeGroup = departmentAdmin ? '' : adminGroup;

  const realEmployees = useMemo(() => {
    if (!adminDepartment) return [];
    return users.filter(
      (entry) =>
        !entry.is_admin &&
        entry.department === adminDepartment &&
        (!scopeGroup || entry.group_name === scopeGroup),
    );
  }, [adminDepartment, scopeGroup, users]);

  const expectedEmployees = departmentAdmin ? realEmployees.length || 0 : EXPECTED_GROUP_EMPLOYEES;
  const departmentGroupCount = useMemo(
    () => new Set(realEmployees.map((entry) => (entry.group_name || '').trim()).filter(Boolean)).size,
    [realEmployees],
  );
  const groupsWithActivityCount = useMemo(
    () => new Set((proxyUsageStats?.group_stats || []).filter((item) => item.request_count > 0).map((item) => item.group_name)).size,
    [proxyUsageStats],
  );

  const employeeSlots = useMemo<EmployeeSlot[]>(() => {
    const registered = realEmployees.map((entry) => ({
      key: `user-${entry.id}`,
      id: entry.id,
      name: formatName(entry),
      email: entry.email,
      sex: entry.sex || null,
      department: entry.department || adminDepartment,
      group_name: entry.group_name || scopeGroup,
      joinedAt: entry.created_at,
      state: 'registered' as const,
    }));

    if (departmentAdmin) {
      return registered;
    }

    const missing = Math.max(0, expectedEmployees - registered.length);
    const placeholders = Array.from({ length: missing }, (_, index) => ({
      key: `placeholder-${index + 1}`,
      id: null,
      name: `Employee Slot ${index + 1}`,
      email: null,
      sex: null,
      department: adminDepartment,
      group_name: scopeGroup,
      joinedAt: null,
      state: 'placeholder' as const,
    }));

    return [...registered, ...placeholders];
  }, [adminDepartment, expectedEmployees, realEmployees, scopeGroup]);

  const employeeIds = useMemo(
    () => new Set(realEmployees.map((entry) => entry.id)),
    [realEmployees],
  );

  const groupScans = useMemo(
    () => scanRows.filter((row) => row.user_id && employeeIds.has(row.user_id)),
    [scanRows, employeeIds],
  );

  const sortedGroupScans = useMemo(
    () =>
      [...groupScans].sort(
        (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
      ),
    [groupScans],
  );

  const scanCountByUser = useMemo(() => {
    const counts = new Map<number, number>();
    for (const row of groupScans) {
      if (!row.user_id) continue;
      counts.set(row.user_id, (counts.get(row.user_id) || 0) + 1);
    }
    return counts;
  }, [groupScans]);

  const latestSessionByUser = useMemo(() => {
    const next = new Map<number, DesktopSessionRow>();
    for (const session of desktopSessions) {
      const current = next.get(session.user_id);
      if (!current) {
        next.set(session.user_id, session);
        continue;
      }

      if (session.online && !current.online) {
        next.set(session.user_id, session);
        continue;
      }

      const currentTs = current.last_heartbeat ? new Date(current.last_heartbeat).getTime() : 0;
      const nextTs = session.last_heartbeat ? new Date(session.last_heartbeat).getTime() : 0;
      if (nextTs > currentTs) {
        next.set(session.user_id, session);
      }
    }
    return next;
  }, [desktopSessions]);

  const visibleDesktopSessions = useMemo(
    () =>
      [...desktopSessions].sort((a, b) => {
        if (a.online !== b.online) {
          return a.online ? -1 : 1;
        }
        const aTs = a.last_heartbeat ? new Date(a.last_heartbeat).getTime() : 0;
        const bTs = b.last_heartbeat ? new Date(b.last_heartbeat).getTime() : 0;
        return bTs - aTs;
      }),
    [desktopSessions],
  );

  const scopedGatewayHistory = useMemo(
    () =>
      [...gatewayHistory].sort((a, b) => {
        const aTs = a.timestamp ? new Date(a.timestamp).getTime() : 0;
        const bTs = b.timestamp ? new Date(b.timestamp).getTime() : 0;
        return bTs - aTs;
      }),
    [gatewayHistory],
  );

  const proxyConnectedEmployees = useMemo(
    () => realEmployees.filter((entry) => isProxyConnected(latestSessionByUser.get(entry.id))).length,
    [latestSessionByUser, realEmployees],
  );

  const suspiciousCount = useMemo(
    () =>
      sortedGroupScans.filter(
        (row) => row.status === 'suspicious' || row.status === 'malicious',
      ).length,
    [sortedGroupScans],
  );

  const latestActivity = useMemo(() => {
    const latest = sortedGroupScans[0]?.created_at || null;
    return formatDateTime(latest);
  }, [sortedGroupScans]);

  const recentScans = useMemo(() => sortedGroupScans.slice(0, 5), [sortedGroupScans]);

  const rangeOptions: { id: MonitoringRange; label: string }[] = [
    { id: 'day', label: '24h' },
    { id: '3days', label: '3 days' },
    { id: 'week', label: '7 days' },
    { id: 'month', label: '30 days' },
  ];

  const memberUsageById = useMemo(() => {
    const next = new Map<number, ProxyUsageMemberRow>();
    for (const item of proxyUsageStats?.member_stats || []) {
      if (item.user_id != null) {
        next.set(item.user_id, item);
      }
    }
    return next;
  }, [proxyUsageStats]);

  const groupUsageByName = useMemo(() => {
    const next = new Map<string, ProxyUsageGroupRow>();
    for (const item of proxyUsageStats?.group_stats || []) {
      next.set(item.group_name, item);
    }
    return next;
  }, [proxyUsageStats]);

  const selectedMemberUsage = selectedMemberId != null ? memberUsageById.get(selectedMemberId) ?? null : null;
  const selectedMemberUser = selectedMemberId != null ? realEmployees.find((entry) => entry.id === selectedMemberId) ?? null : null;
  const selectedMemberSession = selectedMemberId != null ? latestSessionByUser.get(selectedMemberId) : undefined;
  const selectedGroupUsage = selectedGroupName ? groupUsageByName.get(selectedGroupName) ?? null : null;
  const personDetailBackTarget: MonitoringTab = departmentAdmin && selectedGroupName ? 'group-detail' : 'employees';
  const personDetailBackLabel = departmentAdmin && selectedGroupName ? 'Back to Group' : 'Back to Employees';
  const selectedGroupMembers = useMemo(
    () => selectedGroupName
      ? realEmployees.filter((entry) => (entry.group_name || '').trim() === selectedGroupName)
      : [],
    [realEmployees, selectedGroupName],
  );

  const renderRangeSwitcher = () => (
    <div className="flex flex-wrap gap-2">
      {rangeOptions.map((range) => {
        const active = activeRange === range.id;
        return (
          <button
            key={range.id}
            onClick={() => setActiveRange(range.id)}
            className={`rounded-lg px-3 py-1.5 text-xs font-medium transition ${
              active
                ? 'bg-cyan-500 text-white shadow-lg'
                : 'text-slate-300 hover:bg-cyan-500/10 hover:text-cyan-400'
            }`}
          >
            {range.label}
          </button>
        );
      })}
    </div>
  );

  const tabs: { id: MonitoringTab; label: string; icon: typeof Activity }[] = [
    { id: 'overview', label: translateText('Overview'), icon: Activity },
    { id: 'employees', label: translateText('Employees'), icon: Users },
    { id: 'sessions', label: 'Session Presence', icon: Briefcase },
  ];

  return (
    <div className="gateway-start global-scroll flex-1 bg-slate-900">
      <div className="space-y-6 p-4 sm:p-6 xl:p-8">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <h2 className="mb-2 text-3xl font-bold text-white">{translateText('Monitoring')}</h2>
            <p className="text-slate-400">
              {departmentAdmin
                ? 'Department-wide monitoring for the current department admin scope.'
                : 'Group-based monitoring for the current group admin scope.'}
            </p>
          </div>
          <div className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-2 text-sm text-cyan-300">
            {adminDepartment
              ? departmentAdmin
                ? `${adminDepartment} · Department admin`
                : `${adminDepartment} · ${adminGroup}`
              : 'Missing admin scope'}
          </div>
        </div>

        {!adminDepartment || (!departmentAdmin && !adminGroup) ? (
          <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-5 text-amber-200">
            The current admin account does not have a valid department scope yet.
          </div>
        ) : null}

        <div className="grid grid-cols-1 gap-4 md:grid-cols-5">
          <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-4">
            <div className="mb-2 flex items-center justify-between">
              <p className="text-sm text-slate-400">{departmentAdmin ? 'Groups in Department' : 'Expected Employees'}</p>
              <Users className="h-5 w-5 text-cyan-400" />
            </div>
            <p className="text-3xl font-bold text-white">{departmentAdmin ? departmentGroupCount : expectedEmployees}</p>
          </div>
          <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-4">
            <div className="mb-2 flex items-center justify-between">
              <p className="text-sm text-slate-400">{departmentAdmin ? 'Registered Members' : 'Registered Employees'}</p>
              <UserCheck className="h-5 w-5 text-emerald-400" />
            </div>
            <p className="text-3xl font-bold text-white">{realEmployees.length}</p>
          </div>
          <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-4">
            <div className="mb-2 flex items-center justify-between">
              <p className="text-sm text-slate-400">{departmentAdmin ? 'Groups with Activity' : 'Open Slots'}</p>
              <UserPlus className="h-5 w-5 text-amber-400" />
            </div>
            <p className="text-3xl font-bold text-white">
              {departmentAdmin ? groupsWithActivityCount : Math.max(0, expectedEmployees - realEmployees.length)}
            </p>
          </div>
          <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-4">
            <div className="mb-2 flex items-center justify-between">
              <p className="text-sm text-slate-400">Proxy Connected Employees</p>
              <Activity className="h-5 w-5 text-emerald-400" />
            </div>
            <p className="text-3xl font-bold text-white">{proxyConnectedEmployees}</p>
          </div>
          <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-4">
            <div className="mb-2 flex items-center justify-between">
              <p className="text-sm text-slate-400">{departmentAdmin ? 'Department Scans' : 'Group Scans'}</p>
              <Shield className="h-5 w-5 text-cyan-400" />
            </div>
            <p className="text-3xl font-bold text-white">{groupScans.length}</p>
          </div>
        </div>

        <div className="flex gap-2 rounded-xl border border-slate-700 bg-slate-800/50 p-2">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const active = activePanel === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActivePanel(tab.id)}
                className={`flex flex-1 items-center justify-center gap-2 rounded-lg px-4 py-3 transition ${
                  active
                    ? 'bg-cyan-500 text-white shadow-lg'
                    : 'text-slate-300 hover:bg-cyan-500/10 hover:text-cyan-400'
                }`}
              >
                <Icon className="h-4 w-4" />
                <span className="font-medium">{tab.label}</span>
              </button>
            );
          })}
        </div>

        {activePanel === 'overview' && (
          <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1.2fr_0.8fr]">
            <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-6">
              <div className="mb-5 flex items-center justify-between">
                <div>
                  <h3 className="text-xl font-bold text-white">{departmentAdmin ? 'Department Overview' : 'Group Overview'}</h3>
                  <p className="mt-1 text-sm text-slate-400">
                    {departmentAdmin
                      ? 'Built from the employees registered in the current admin department.'
                      : 'Built from the employees registered in the current admin group.'}
                  </p>
                </div>
                <div className="flex flex-col items-end gap-2">
                  {renderRangeSwitcher()}
                  <span className="text-xs text-slate-500">
                    {proxyUsageStats
                      ? `Window: last ${proxyUsageStats.days} day${proxyUsageStats.days > 1 ? 's' : ''}`
                      : loading
                        ? 'Loading...'
                        : 'No usage window yet'}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                  <p className="text-sm text-slate-400">{departmentAdmin ? 'Latest Department Activity' : 'Latest Group Activity'}</p>
                  <p className="mt-3 text-lg font-semibold text-white">{latestActivity}</p>
                </div>
                <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                  <p className="text-sm text-slate-400">Suspicious or Malicious Scans</p>
                  <p className="mt-3 text-lg font-semibold text-amber-300">{suspiciousCount}</p>
                </div>
                <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                  <p className="text-sm text-slate-400">Registered vs Expected</p>
                  <p className="mt-3 text-lg font-semibold text-white">
                    {departmentAdmin ? `${realEmployees.length} total member(s)` : `${realEmployees.length} / ${expectedEmployees}`}
                  </p>
                </div>
              </div>

              <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-4">
                <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                  <div className="mb-2 flex items-center justify-between">
                    <p className="text-sm text-slate-400">Proxy Requests</p>
                    <Activity className="h-4 w-4 text-cyan-300" />
                  </div>
                  <p className="text-2xl font-bold text-white">
                    {proxyUsageStats?.group_summary.request_count ?? 0}
                  </p>
                </div>
                <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                  <div className="mb-2 flex items-center justify-between">
                    <p className="text-sm text-slate-400">Blocked by Proxy</p>
                    <Shield className="h-4 w-4 text-red-300" />
                  </div>
                  <p className="text-2xl font-bold text-red-300">
                    {proxyUsageStats?.group_summary.blocked_count ?? 0}
                  </p>
                </div>
                <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                  <div className="mb-2 flex items-center justify-between">
                    <p className="text-sm text-slate-400">Unique Sites</p>
                    <Globe className="h-4 w-4 text-sky-300" />
                  </div>
                  <p className="text-2xl font-bold text-white">
                    {proxyUsageStats?.group_summary.unique_sites ?? 0}
                  </p>
                </div>
                <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                  <div className="mb-2 flex items-center justify-between">
                    <p className="text-sm text-slate-400">Members with Activity</p>
                    <Users className="h-4 w-4 text-emerald-300" />
                  </div>
                  <p className="text-2xl font-bold text-white">
                    {proxyUsageStats?.group_summary.unique_members ?? 0}
                  </p>
                </div>
              </div>

              <div className="mt-6 grid grid-cols-1 gap-4 xl:grid-cols-[1.1fr_0.9fr]">
                <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                  <div className="mb-4 flex items-center gap-2">
                    <Globe className="h-5 w-5 text-cyan-300" />
                    <h4 className="text-lg font-semibold text-white">Most Used Sites</h4>
                  </div>
                  {proxyUsageStats?.top_sites?.length ? (
                    <div className="gateway-panel-scroll space-y-3">
                      {proxyUsageStats.top_sites.map((site) => (
                        <div key={site.host} className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <SiteIdentity host={site.host} />
                              <p className="mt-1 text-xs text-slate-400">
                                {site.unique_members ?? 0} member(s) · Last seen {formatDateTime(site.last_seen || null)}
                              </p>
                            </div>
                            <div className="text-right">
                              <p className="text-lg font-bold text-white">{site.request_count}</p>
                              <p className="text-xs text-slate-500">requests</p>
                            </div>
                          </div>
                          <SiteStatusBadges site={site} />
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="rounded-xl border border-dashed border-slate-700 bg-slate-950/35 p-5 text-sm text-slate-400">
                      No proxy usage recorded in the selected period yet.
                    </div>
                  )}
                </div>

                <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                  <div className="mb-4 flex items-center gap-2">
                    <BarChart3 className="h-5 w-5 text-cyan-300" />
                    <h4 className="text-lg font-semibold text-white">Daily Activity</h4>
                  </div>
                  {proxyUsageStats?.daily_stats?.length ? (
                    <div className="gateway-panel-scroll space-y-3">
                      {proxyUsageStats.daily_stats.map((entry) => (
                        <div key={entry.date} className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                          <div className="flex items-center justify-between gap-3">
                            <div>
                              <p className="text-sm font-semibold text-white">{entry.date}</p>
                              <p className="mt-1 text-xs text-slate-400">
                                {entry.unique_members} member(s) · {entry.unique_sites} site(s)
                              </p>
                            </div>
                            <div className="text-right">
                              <p className="text-lg font-bold text-white">{entry.request_count}</p>
                              <p className="text-xs text-slate-500">requests</p>
                            </div>
                          </div>
                          <div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-800">
                            <div
                              className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500"
                              style={{
                                width: `${Math.max(
                                  8,
                                  Math.min(
                                    100,
                                    (entry.request_count /
                                      Math.max(
                                        1,
                                        ...((proxyUsageStats?.daily_stats || []).map((item) => item.request_count)),
                                      )) *
                                      100,
                                  ),
                                )}%`,
                              }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="rounded-xl border border-dashed border-slate-700 bg-slate-950/35 p-5 text-sm text-slate-400">
                      Daily proxy activity will appear here once group members browse through the attached proxy.
                    </div>
                  )}
                </div>
              </div>

              <div className="mt-6 grid grid-cols-1 gap-4 xl:grid-cols-2">
                <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                  <div className="mb-4 flex items-center gap-2">
                    <Users className="h-5 w-5 text-cyan-300" />
                    <h4 className="text-lg font-semibold text-white">Usage by Person</h4>
                  </div>
                  {proxyUsageStats?.member_stats?.length ? (
                    <div className="gateway-panel-scroll space-y-3">
                      {proxyUsageStats.member_stats.map((member) => (
                        <button
                          key={`${member.user_id ?? member.email ?? member.name}`}
                          type="button"
                          disabled={member.user_id == null}
                          onClick={() => {
                            if (member.user_id != null) {
                              setSelectedMemberId(member.user_id);
                              setActivePanel('person-detail');
                            }
                          }}
                          className="w-full rounded-lg border border-slate-700 bg-slate-950/50 p-3 text-left transition hover:border-cyan-500/40 hover:bg-slate-900/70 disabled:cursor-default"
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <p className="truncate text-sm font-semibold text-white">{member.name}</p>
                              <p className="mt-1 text-xs text-slate-400">
                                {member.email || 'No email'} · Last seen {formatDateTime(member.last_seen || null)}
                              </p>
                            </div>
                            <div className="text-right">
                              <p className="text-lg font-bold text-white">{member.request_count}</p>
                              <p className="text-xs text-slate-500">requests</p>
                            </div>
                          </div>
                          <div className="mt-3 flex flex-wrap gap-2 text-xs">
                            <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-emerald-300">
                              Allowed {member.allowed_count}
                            </span>
                            <span className="rounded-full border border-red-500/30 bg-red-500/10 px-2.5 py-1 text-red-300">
                              Blocked {member.blocked_count}
                            </span>
                            <span className="rounded-full border border-slate-700 bg-slate-800/70 px-2.5 py-1 text-slate-300">
                              Unique sites {member.unique_sites}
                            </span>
                          </div>
                          <div className="mt-3 space-y-2">
                            {member.top_sites.length ? (
                              member.top_sites.slice(0, 10).map((site) => (
                                <div
                                  key={`${member.name}-${site.host}`}
                                  className="rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-2"
                                >
                                  <div className="flex items-center justify-between gap-3">
                                    <SiteIdentity host={site.host} compact />
                                    <span className="text-xs font-semibold text-cyan-300">{site.request_count} hit(s)</span>
                                  </div>
                                  <SiteStatusBadges site={site} />
                                </div>
                              ))
                            ) : (
                              <p className="text-sm text-slate-400">No site activity yet.</p>
                            )}
                          </div>
                        </button>
                      ))}
                    </div>
                  ) : (
                    <div className="rounded-xl border border-dashed border-slate-700 bg-slate-950/35 p-5 text-sm text-slate-400">
                      No member usage data in the selected window.
                    </div>
                  )}
                </div>

                <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                  <div className="mb-4 flex items-center gap-2">
                    <Briefcase className="h-5 w-5 text-cyan-300" />
                    <h4 className="text-lg font-semibold text-white">Usage by Group</h4>
                  </div>
                  {proxyUsageStats?.group_stats?.length ? (
                    <div className="gateway-panel-scroll space-y-3">
                      {proxyUsageStats.group_stats.map((group) => (
                        <button
                          key={group.group_name}
                          type="button"
                          onClick={() => {
                            setSelectedGroupName(group.group_name);
                            setActivePanel('group-detail');
                          }}
                          className="w-full rounded-lg border border-slate-700 bg-slate-950/50 p-3 text-left transition hover:border-cyan-500/40 hover:bg-slate-900/70"
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <p className="truncate text-sm font-semibold text-white">{group.group_name}</p>
                              <p className="mt-1 text-xs text-slate-400">
                                {group.unique_members} member(s) · {group.unique_sites} site(s) · Last seen {formatDateTime(group.last_seen || null)}
                              </p>
                            </div>
                            <div className="text-right">
                              <p className="text-lg font-bold text-white">{group.request_count}</p>
                              <p className="text-xs text-slate-500">requests</p>
                            </div>
                          </div>
                          <div className="mt-3 flex flex-wrap gap-2 text-xs">
                            <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-emerald-300">
                              Allowed {group.allowed_count}
                            </span>
                            <span className="rounded-full border border-red-500/30 bg-red-500/10 px-2.5 py-1 text-red-300">
                              Blocked {group.blocked_count}
                            </span>
                          </div>
                          <div className="mt-3 space-y-2">
                            {group.top_sites.length ? (
                              group.top_sites.slice(0, 10).map((site) => (
                                <div
                                  key={`${group.group_name}-${site.host}`}
                                  className="rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-2"
                                >
                                  <div className="flex items-center justify-between gap-3">
                                    <SiteIdentity host={site.host} compact />
                                    <span className="text-xs font-semibold text-cyan-300">{site.request_count} hit(s)</span>
                                  </div>
                                  <SiteStatusBadges site={site} />
                                </div>
                              ))
                            ) : (
                              <p className="text-sm text-slate-400">No site activity yet.</p>
                            )}
                          </div>
                        </button>
                      ))}
                    </div>
                  ) : (
                    <div className="rounded-xl border border-dashed border-slate-700 bg-slate-950/35 p-5 text-sm text-slate-400">
                      No group usage data in the selected window.
                    </div>
                  )}
                </div>
              </div>

              <div className="mt-6">
                <h4 className="mb-3 text-lg font-semibold text-white">{departmentAdmin ? 'Department Members' : 'Employee Slots'}</h4>
                <div className="space-y-3">
                  {employeeSlots.map((entry) => {
                    const latestSession = entry.id ? latestSessionByUser.get(entry.id) : undefined;
                    const status = connectionSummary(latestSession);
                    return (
                      <div
                        key={entry.key}
                        className={`rounded-xl border p-4 ${
                          entry.state === 'registered'
                            ? 'border-slate-700 bg-slate-900/50'
                            : 'border-dashed border-slate-700 bg-slate-950/35'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-4">
                          <div>
                            <p className="text-base font-semibold text-white">{entry.name}</p>
                            <p className="mt-1 text-sm text-slate-400">
                              {entry.email || 'Waiting for first employee login'}
                            </p>
                            {latestSession ? (
                              <p className={`mt-2 text-xs ${status.tone}`}>
                                {status.label}
                              </p>
                            ) : null}
                          </div>
                          <span
                            className={`rounded-full border px-3 py-1 text-xs font-semibold ${
                              entry.state !== 'registered'
                                ? 'border-slate-700 bg-slate-800/70 text-slate-400'
                                : status.badgeClass
                            }`}
                          >
                            {entry.state !== 'registered'
                              ? 'Placeholder'
                              : status.badge}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-6">
              <div className="mb-4 flex items-center gap-2">
                <Clock3 className="h-5 w-5 text-cyan-300" />
                <h3 className="text-xl font-bold text-white">Recent Group Scans</h3>
              </div>
              {recentScans.length ? (
                <div className="gateway-panel-scroll space-y-3">
                  {recentScans.map((scan) => (
                    <div key={scan.id} className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <p className="truncate text-sm font-semibold text-white">{scan.target}</p>
                          <p className="mt-1 text-xs text-slate-400">
                            {scan.scan_type} · {formatDateTime(scan.created_at)}
                          </p>
                        </div>
                        <span
                          className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${
                            scan.status === 'malicious'
                              ? 'border-red-500/30 bg-red-500/10 text-red-300'
                              : scan.status === 'suspicious'
                                ? 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                                : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                          }`}
                        >
                          {scan.status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="rounded-xl border border-dashed border-slate-700 bg-slate-950/35 p-5 text-sm text-slate-400">
                  No scans from the current {departmentAdmin ? 'department' : 'group'} yet. Once members start scanning, this panel
                  will populate automatically.
                </div>
              )}
            </div>
          </div>
        )}

        {activePanel === 'employees' && (
          <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-6">
            <div className="mb-5 flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
              <div>
                <h3 className="text-xl font-bold text-white">
                  {departmentAdmin ? 'Groups in SSI Department' : 'Employees in Current Group'}
                </h3>
                <p className="mt-1 text-sm text-slate-400">
                  {departmentAdmin
                    ? 'Per-group statistics for the department. Open a group to see its members and their usage.'
                    : 'Per-person proxy usage and most visited sites in the selected time window.'}
                </p>
              </div>
              <div className="flex flex-col items-end gap-2">
                {renderRangeSwitcher()}
                <span className="text-xs text-slate-500">
                  {proxyUsageStats
                    ? `Window: last ${proxyUsageStats.days} day${proxyUsageStats.days > 1 ? 's' : ''}`
                    : 'Usage window loading...'}
                </span>
              </div>
            </div>
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              {departmentAdmin ? (
                (proxyUsageStats?.group_stats || []).length ? (
                  (proxyUsageStats?.group_stats || []).map((group) => (
                    <button
                      key={`dept-group-${group.group_name}`}
                      type="button"
                      onClick={() => {
                        setSelectedGroupName(group.group_name);
                        setActivePanel('group-detail');
                      }}
                      className="rounded-xl border border-slate-700 bg-slate-900/50 p-5 text-left transition hover:border-cyan-500/40 hover:bg-slate-900/70"
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div>
                          <p className="text-lg font-semibold text-white">{group.group_name}</p>
                          <p className="mt-1 text-sm text-slate-400">
                            {group.unique_members} member(s) · {group.unique_sites} unique site(s)
                          </p>
                        </div>
                        <div className="flex flex-col items-end gap-2">
                          <span className="rounded-full border border-slate-700 bg-slate-800/70 px-3 py-1 text-xs text-slate-300">
                            {group.department}
                          </span>
                          <span className="rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-xs font-semibold text-cyan-300">
                            Open group
                          </span>
                        </div>
                      </div>

                      <div className="mt-5 grid grid-cols-2 gap-3">
                        <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Requests</p>
                          <p className="mt-2 text-sm font-medium text-slate-200">{group.request_count}</p>
                        </div>
                        <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Members with Activity</p>
                          <p className="mt-2 text-sm font-medium text-slate-200">{group.unique_members}</p>
                        </div>
                        <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Allowed</p>
                          <p className="mt-2 text-sm font-medium text-emerald-300">{group.allowed_count}</p>
                        </div>
                        <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Blocked</p>
                          <p className="mt-2 text-sm font-medium text-red-300">{group.blocked_count}</p>
                        </div>
                        <div className="col-span-2 rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Top Sites in Selected Window</p>
                          <div className="mt-3 space-y-2">
                            {group.top_sites.length ? (
                              group.top_sites.slice(0, 8).map((site) => (
                                <div
                                  key={`dept-group-site-${group.group_name}-${site.host}`}
                                  className="rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-2"
                                >
                                  <div className="flex items-center justify-between gap-3">
                                    <SiteIdentity host={site.host} compact />
                                    <span className="text-xs font-semibold text-cyan-300">
                                      {site.request_count} hit(s)
                                    </span>
                                  </div>
                                  <SiteStatusBadges site={site} />
                                </div>
                              ))
                            ) : (
                              <p className="text-sm text-slate-400">No proxy usage yet for this group.</p>
                            )}
                          </div>
                        </div>
                      </div>
                    </button>
                  ))
                ) : (
                  <div className="rounded-xl border border-dashed border-slate-700 bg-slate-950/35 p-5 text-sm text-slate-400">
                    No group activity found in the selected period.
                  </div>
                )
              ) : (
                employeeSlots.map((entry) => {
                  const scanCount = entry.id ? scanCountByUser.get(entry.id) || 0 : 0;
                  const latestSession = entry.id ? latestSessionByUser.get(entry.id) : undefined;
                  const status = connectionSummary(latestSession);
                  const usageStats = entry.id ? memberUsageById.get(entry.id) : undefined;
                  return (
                    <button
                      key={entry.key}
                      type="button"
                      disabled={entry.state !== 'registered' || !entry.id}
                      onClick={() => {
                        if (entry.id) {
                          setSelectedMemberId(entry.id);
                          setActivePanel('person-detail');
                        }
                      }}
                      className={`rounded-xl border p-5 text-left transition ${
                        entry.state === 'registered'
                          ? 'border-slate-700 bg-slate-900/50 hover:border-cyan-500/40 hover:bg-slate-900/70'
                          : 'border-dashed border-slate-700 bg-slate-950/35'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div>
                          <p className="text-lg font-semibold text-white">{entry.name}</p>
                          <p className="mt-1 text-sm text-slate-400">
                            {entry.email || 'Reserved employee slot'}
                          </p>
                        </div>
                        <div className="flex flex-col items-end gap-2">
                          <span className="rounded-full border border-slate-700 bg-slate-800/70 px-3 py-1 text-xs text-slate-300">
                            {entry.department || '-'}
                          </span>
                          <span
                            className={`rounded-full border px-3 py-1 text-xs font-semibold ${
                              entry.state !== 'registered'
                                ? 'border-slate-700 bg-slate-800/70 text-slate-400'
                                : status.badgeClass
                            }`}
                          >
                            {entry.state !== 'registered'
                              ? 'Placeholder'
                              : status.badge}
                          </span>
                        </div>
                      </div>

                      <div className="mt-5 grid grid-cols-2 gap-3">
                        <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Group</p>
                          <p className="mt-2 text-sm font-medium text-slate-200">{entry.group_name || '-'}</p>
                        </div>
                        <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Scans</p>
                          <p className="mt-2 text-sm font-medium text-slate-200">{scanCount}</p>
                        </div>
                        <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Proxy Requests</p>
                          <p className="mt-2 text-sm font-medium text-slate-200">{usageStats?.request_count ?? 0}</p>
                        </div>
                        <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Most Used Site</p>
                          <p className="mt-2 truncate text-sm font-medium text-slate-200">
                            {usageStats?.top_sites?.[0]?.host || 'No proxy usage yet'}
                          </p>
                        </div>
                        <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Sex</p>
                          <p className="mt-2 text-sm font-medium text-slate-200">{entry.sex || 'Pending'}</p>
                        </div>
                        <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Joined</p>
                          <p className="mt-2 text-sm font-medium text-slate-200">{formatDate(entry.joinedAt)}</p>
                        </div>
                        <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Device</p>
                          <p className="mt-2 text-sm font-medium text-slate-200">
                            {latestSession?.hostname || 'No active session'}
                          </p>
                        </div>
                        <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Last heartbeat</p>
                          <p className="mt-2 text-sm font-medium text-slate-200">
                            {latestSession ? formatDateTime(latestSession.last_heartbeat || null) : 'No session yet'}
                          </p>
                        </div>
                        <div className="col-span-2 rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Connection Status</p>
                          <p className={`mt-2 text-sm font-medium ${status.tone}`}>
                            {entry.state !== 'registered'
                              ? 'This employee slot is still empty.'
                              : status.label}
                          </p>
                        </div>
                        <div className="col-span-2 rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Usage Summary in Selected Window</p>
                          {usageStats ? (
                            <>
                              <div className="mt-2 flex flex-wrap gap-2 text-xs">
                                <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-emerald-300">
                                  Allowed {usageStats.allowed_count}
                                </span>
                                <span className="rounded-full border border-red-500/30 bg-red-500/10 px-2.5 py-1 text-red-300">
                                  Blocked {usageStats.blocked_count}
                                </span>
                                <span className="rounded-full border border-slate-700 bg-slate-800/70 px-2.5 py-1 text-slate-300">
                                  Unique sites {usageStats.unique_sites}
                                </span>
                              </div>
                              <div className="mt-3 space-y-2">
                                {usageStats.top_sites.length ? (
                                  usageStats.top_sites.map((site) => (
                                    <div
                                      key={`${entry.key}-${site.host}`}
                                      className="rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-2"
                                    >
                                      <div className="flex items-center justify-between gap-3">
                                        <SiteIdentity host={site.host} compact />
                                        <span className="text-xs font-semibold text-cyan-300">
                                          {site.request_count} hit(s)
                                        </span>
                                      </div>
                                      <SiteStatusBadges site={site} />
                                    </div>
                                  ))
                                ) : (
                                  <p className="text-sm text-slate-400">
                                    No proxy events recorded for this member in the selected period.
                                  </p>
                                )}
                              </div>
                            </>
                          ) : (
                            <p className="mt-2 text-sm text-slate-400">
                              No proxy events recorded for this member in the selected period.
                            </p>
                          )}
                        </div>
                      </div>
                    </button>
                  );
                })
              )}
            </div>
          </div>
        )}

        {activePanel === 'person-detail' && (
          <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-6">
            <div className="mb-5 flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
              <div>
                <button
                  type="button"
                  onClick={() => setActivePanel(personDetailBackTarget)}
                  className="mb-3 inline-flex items-center gap-2 text-sm text-cyan-300 hover:text-cyan-200"
                >
                  {personDetailBackLabel}
                </button>
                <h3 className="text-xl font-bold text-white">
                  {selectedMemberUser ? formatName(selectedMemberUser) : selectedMemberUsage?.name || 'User Details'}
                </h3>
                <p className="mt-1 text-sm text-slate-400">
                  Detailed proxy usage, most visited sites, and session context for the selected user.
                </p>
              </div>
              <div className="flex flex-col items-end gap-2">
                {renderRangeSwitcher()}
                <span className="text-xs text-slate-500">
                  {proxyUsageStats
                    ? `Window: last ${proxyUsageStats.days} day${proxyUsageStats.days > 1 ? 's' : ''}`
                    : 'Usage window loading...'}
                </span>
              </div>
            </div>

            {selectedMemberUsage ? (
              <div className="space-y-6">
                <div className="grid grid-cols-1 gap-4 md:grid-cols-5">
                  <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                    <p className="text-sm text-slate-400">Requests</p>
                    <p className="mt-3 text-2xl font-bold text-white">{selectedMemberUsage.request_count}</p>
                  </div>
                  <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                    <p className="text-sm text-slate-400">Allowed</p>
                    <p className="mt-3 text-2xl font-bold text-emerald-300">{selectedMemberUsage.allowed_count}</p>
                  </div>
                  <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                    <p className="text-sm text-slate-400">Blocked</p>
                    <p className="mt-3 text-2xl font-bold text-red-300">{selectedMemberUsage.blocked_count}</p>
                  </div>
                  <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                    <p className="text-sm text-slate-400">Unique Sites</p>
                    <p className="mt-3 text-2xl font-bold text-white">{selectedMemberUsage.unique_sites}</p>
                  </div>
                  <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                    <p className="text-sm text-slate-400">Last Activity</p>
                    <p className="mt-3 text-sm font-semibold text-white">{formatDateTime(selectedMemberUsage.last_seen || null)}</p>
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-4 xl:grid-cols-[0.95fr_1.05fr]">
                  <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                    <h4 className="mb-4 text-lg font-semibold text-white">Identity & Session</h4>
                    <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                      <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                        <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Email</p>
                        <p className="mt-2 text-sm font-medium text-slate-200">{selectedMemberUsage.email || selectedMemberUser?.email || '-'}</p>
                      </div>
                      <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                        <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Department</p>
                        <p className="mt-2 text-sm font-medium text-slate-200">{selectedMemberUser?.department || adminDepartment || '-'}</p>
                      </div>
                      <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                        <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Group</p>
                        <p className="mt-2 text-sm font-medium text-slate-200">{selectedMemberUser?.group_name || adminGroup || '-'}</p>
                      </div>
                      <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                        <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Current Device</p>
                        <p className="mt-2 text-sm font-medium text-slate-200">{selectedMemberSession?.hostname || selectedMemberSession?.device_id || 'No active session'}</p>
                      </div>
                    </div>
                  </div>

                  <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                    <h4 className="mb-4 text-lg font-semibold text-white">Most Used Sites</h4>
                    <div className="gateway-panel-scroll space-y-3">
                      {selectedMemberUsage.top_sites.length ? (
                        selectedMemberUsage.top_sites.map((site) => (
                          <div key={`detail-${selectedMemberUsage.name}-${site.host}`} className="rounded-lg border border-slate-700 bg-slate-950/50 px-3 py-3">
                            <div className="flex items-center justify-between gap-3">
                              <SiteIdentity host={site.host} />
                              <span className="text-sm font-semibold text-cyan-300">{site.request_count} hit(s)</span>
                            </div>
                            <SiteStatusBadges site={site} />
                          </div>
                        ))
                      ) : (
                        <p className="text-sm text-slate-400">No recorded browsing yet in the selected window.</p>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="rounded-xl border border-dashed border-slate-700 bg-slate-950/35 p-5 text-sm text-slate-400">
                No detailed usage available yet for this user in the selected period.
              </div>
            )}
          </div>
        )}

        {activePanel === 'group-detail' && (
          <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-6">
            <div className="mb-5 flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
              <div>
                <button
                  type="button"
                  onClick={() => setActivePanel(departmentAdmin ? 'employees' : 'overview')}
                  className="mb-3 inline-flex items-center gap-2 text-sm text-cyan-300 hover:text-cyan-200"
                >
                  {departmentAdmin ? 'Back to Groups' : 'Back to Overview'}
                </button>
                <h3 className="text-xl font-bold text-white">{selectedGroupUsage?.group_name || selectedGroupName || 'Group Details'}</h3>
                <p className="mt-1 text-sm text-slate-400">
                  Detailed proxy usage, most visited sites, and group-level activity for the selected group.
                </p>
              </div>
              <div className="flex flex-col items-end gap-2">
                {renderRangeSwitcher()}
                <span className="text-xs text-slate-500">
                  {proxyUsageStats
                    ? `Window: last ${proxyUsageStats.days} day${proxyUsageStats.days > 1 ? 's' : ''}`
                    : 'Usage window loading...'}
                </span>
              </div>
            </div>

            {selectedGroupUsage ? (
              <div className="space-y-6">
                <div className="grid grid-cols-1 gap-4 md:grid-cols-5">
                  <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                    <p className="text-sm text-slate-400">Requests</p>
                    <p className="mt-3 text-2xl font-bold text-white">{selectedGroupUsage.request_count}</p>
                  </div>
                  <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                    <p className="text-sm text-slate-400">Allowed</p>
                    <p className="mt-3 text-2xl font-bold text-emerald-300">{selectedGroupUsage.allowed_count}</p>
                  </div>
                  <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                    <p className="text-sm text-slate-400">Blocked</p>
                    <p className="mt-3 text-2xl font-bold text-red-300">{selectedGroupUsage.blocked_count}</p>
                  </div>
                  <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                    <p className="text-sm text-slate-400">Members with Activity</p>
                    <p className="mt-3 text-2xl font-bold text-white">{selectedGroupUsage.unique_members}</p>
                  </div>
                  <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                    <p className="text-sm text-slate-400">Unique Sites</p>
                    <p className="mt-3 text-2xl font-bold text-white">{selectedGroupUsage.unique_sites}</p>
                  </div>
                </div>

                <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                  <h4 className="mb-4 text-lg font-semibold text-white">Most Used Sites in This Group</h4>
                  <div className="gateway-panel-scroll space-y-3">
                    {selectedGroupUsage.top_sites.length ? (
                      selectedGroupUsage.top_sites.map((site) => (
                        <div key={`group-detail-${selectedGroupUsage.group_name}-${site.host}`} className="rounded-lg border border-slate-700 bg-slate-950/50 px-3 py-3">
                          <div className="flex items-center justify-between gap-3">
                            <SiteIdentity host={site.host} />
                            <span className="text-sm font-semibold text-cyan-300">{site.request_count} hit(s)</span>
                          </div>
                          <SiteStatusBadges site={site} />
                        </div>
                      ))
                    ) : (
                      <p className="text-sm text-slate-400">No recorded browsing yet in the selected window.</p>
                    )}
                  </div>
                </div>

                <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                  <h4 className="mb-4 text-lg font-semibold text-white">Members of This Group</h4>
                  <div className="gateway-panel-scroll space-y-3">
                    {selectedGroupMembers.length ? (
                      selectedGroupMembers.map((member) => {
                        const memberUsage = memberUsageById.get(member.id) ?? null;
                        const session = latestSessionByUser.get(member.id);
                        const status = connectionSummary(session);
                        return (
                          <button
                            key={`group-member-${member.id}`}
                            type="button"
                            onClick={() => {
                              setSelectedMemberId(member.id);
                              setActivePanel('person-detail');
                            }}
                            className="w-full rounded-lg border border-slate-700 bg-slate-950/50 p-3 text-left transition hover:border-cyan-500/40 hover:bg-slate-900/70"
                          >
                            <div className="flex items-start justify-between gap-3">
                              <div className="min-w-0">
                                <p className="truncate text-sm font-semibold text-white">{formatName(member)}</p>
                                <p className="mt-1 truncate text-xs text-slate-400">{member.email}</p>
                                <p className={`mt-2 text-xs ${status.tone}`}>{status.label}</p>
                              </div>
                              <div className="text-right">
                                <p className="text-lg font-bold text-white">{memberUsage?.request_count ?? 0}</p>
                                <p className="text-xs text-slate-500">requests</p>
                              </div>
                            </div>
                            <div className="mt-3 flex flex-wrap gap-2 text-xs">
                              <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-emerald-300">
                                Allowed {memberUsage?.allowed_count ?? 0}
                              </span>
                              <span className="rounded-full border border-red-500/30 bg-red-500/10 px-2.5 py-1 text-red-300">
                                Blocked {memberUsage?.blocked_count ?? 0}
                              </span>
                              <span className="rounded-full border border-slate-700 bg-slate-800/70 px-2.5 py-1 text-slate-300">
                                Unique sites {memberUsage?.unique_sites ?? 0}
                              </span>
                            </div>
                          </button>
                        );
                      })
                    ) : (
                      <p className="text-sm text-slate-400">No registered members found for this group yet.</p>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <div className="rounded-xl border border-dashed border-slate-700 bg-slate-950/35 p-5 text-sm text-slate-400">
                No detailed usage available yet for this group in the selected period.
              </div>
            )}
          </div>
        )}

        {activePanel === 'sessions' && (
          <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-6">
            <div className="mb-5 flex items-center gap-2">
              <Briefcase className="h-5 w-5 text-cyan-300" />
              <h3 className="text-xl font-bold text-white">Client Session Presence</h3>
            </div>

            <div className="mb-5 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4 text-sm leading-6 text-slate-300">
              Presence is based on explicit app and browser heartbeats, while proxy compliance is
              tracked separately. A worker can be online but still show Proxy Disabled or Proxy
              Mismatch if the enterprise proxy is no longer active.
            </div>

            <div className="mb-5 grid grid-cols-1 gap-4 lg:grid-cols-[0.9fr_1.1fr]">
              <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">
                  {departmentAdmin ? 'Department Proxy Assignment' : 'Group Proxy Assignment'}
                </p>
                {groupProxyAssignment ? (
                  <>
                    <p className="mt-3 text-lg font-semibold text-white">
                      {groupProxyAssignment.proxy_host}:{groupProxyAssignment.proxy_port}
                    </p>
                    <p className="mt-1 text-sm text-slate-400">
                      {groupProxyAssignment.department}
                      {groupProxyAssignment.scope === 'department'
                        ? ' · Department proxy'
                        : ` · ${groupProxyAssignment.group_name}`}
                    </p>
                    <p className="mt-2 text-xs text-slate-500">
                      {groupProxyAssignment.note || 'Proxy assignment ready for the current admin scope.'}
                    </p>
                  </>
                ) : (
                  <p className="mt-3 text-sm text-slate-400">No proxy assignment defined for this admin scope yet.</p>
                )}
              </div>

              <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Recent Attached Gateway Usage</p>
                {scopedGatewayHistory.length ? (
                  <div className="mt-3 space-y-3">
                    {scopedGatewayHistory.slice(0, 4).map((event, index) => (
                      <div key={`${event.timestamp || 't'}-${index}`} className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <SiteIdentity host={event.host || 'Unknown target'} />
                            <p className="mt-1 text-xs text-slate-400">
                              {(event.user_name || event.user_email || 'Unattached worker')} · {event.hostname || 'Unknown device'}
                            </p>
                          </div>
                          <div className="flex items-center gap-2">
                            {event.port ? (
                              <span className="rounded-full border border-slate-700 bg-slate-900/70 px-2.5 py-1 text-xs font-semibold text-slate-300">
                                Port {event.port}
                              </span>
                            ) : null}
                            <span
                              className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${
                                event.blocked
                                  ? 'border-red-500/30 bg-red-500/10 text-red-300'
                                  : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                              }`}
                            >
                              {event.blocked ? 'Blocked' : 'Allowed'}
                            </span>
                          </div>
                        </div>
                        <p className="mt-2 text-xs text-slate-500">
                          {(event.method || 'HTTP').toUpperCase()} · {formatDateTime(event.timestamp || null)}
                        </p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="mt-3 text-sm text-slate-400">
                    No attached gateway events yet. Once workers use the proxy, events will appear here under the active session.
                  </p>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              {visibleDesktopSessions.length ? visibleDesktopSessions.map((session) => (
                <div key={session.session_id} className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                  {(() => {
                    const proxyBadge = proxyStateMeta(session.proxy_state);
                    return (
                      <>
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-white">{session.user_name}</p>
                      <p className="mt-1 text-xs text-slate-400">{session.email}</p>
                    </div>
                    <div className="flex flex-col items-end gap-2">
                      <span
                        className={`rounded-full border px-3 py-1 text-xs font-semibold ${
                          session.online
                            ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                            : 'border-slate-700 bg-slate-800/70 text-slate-300'
                        }`}
                      >
                        {session.online ? 'Online' : 'Offline'}
                      </span>
                      <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${proxyBadge.className}`}>
                        {proxyBadge.label}
                      </span>
                    </div>
                  </div>

                  <div className="mt-4 grid grid-cols-2 gap-3">
                    <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                      <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Device</p>
                      <p className="mt-2 text-sm font-medium text-slate-200">
                        {session.hostname || session.device_id || 'Unknown device'}
                      </p>
                    </div>
                    <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                      <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Heartbeat</p>
                      <p className="mt-2 text-sm font-medium text-slate-200">
                        {formatDateTime(session.last_heartbeat || null)}
                      </p>
                    </div>
                    <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                      <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Platform</p>
                      <p className="mt-2 text-sm font-medium text-slate-200">
                        {session.platform || 'Unknown'}
                      </p>
                    </div>
                    <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                      <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Disconnect</p>
                      <p className="mt-2 text-sm font-medium text-slate-200">
                        {session.disconnect_reason || 'Active'}
                      </p>
                    </div>
                    <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                      <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Expected Proxy</p>
                      <p className="mt-2 text-sm font-medium text-slate-200">
                        {formatProxyEndpoint(session.assigned_proxy_host, session.assigned_proxy_port)}
                      </p>
                    </div>
                    <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                      <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Detected Proxy</p>
                      <p className="mt-2 text-sm font-medium text-slate-200">
                        {session.proxy_state === 'browser-unavailable'
                          ? 'Unavailable in browser mode'
                          : formatProxyEndpoint(session.proxy_host, session.proxy_port)}
                      </p>
                    </div>
                  </div>
                      </>
                    );
                  })()}
                </div>
              )) : (
                <div className="rounded-xl border border-dashed border-slate-700 bg-slate-950/35 p-5 text-sm text-slate-400">
                  No sessions detected yet for the current group. Once workers open the desktop app
                  or browser interface and authenticate, their presence will appear here automatically.
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

