import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  Briefcase,
  Clock3,
  Shield,
  UserCheck,
  UserPlus,
  Users,
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useLanguage } from '../contexts/LanguageContext';
import { apiUrl } from '../config/api';

type MonitoringTab = 'overview' | 'employees' | 'sessions';

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
  started_at?: string | null;
  last_heartbeat?: string | null;
  online: boolean;
  disconnect_reason?: string | null;
  seconds_since_last_heartbeat?: number | null;
};

type GatewayHistoryRow = {
  timestamp?: string | null;
  host?: string | null;
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
  proxy_host: string;
  proxy_port: number;
  enabled: boolean;
  note?: string | null;
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

export function GatewayStartView() {
  const { token, user } = useAuth();
  const { translateText } = useLanguage();
  const [activePanel, setActivePanel] = useState<MonitoringTab>('overview');
  const [users, setUsers] = useState<UserRow[]>([]);
  const [scanRows, setScanRows] = useState<ScanRow[]>([]);
  const [desktopSessions, setDesktopSessions] = useState<DesktopSessionRow[]>([]);
  const [gatewayHistory, setGatewayHistory] = useState<GatewayHistoryRow[]>([]);
  const [groupProxyAssignment, setGroupProxyAssignment] = useState<GroupProxyAssignment | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!token) return;

    const loadMonitoringData = async () => {
      setLoading(true);
      try {
        const [usersRes, scansRes, sessionsRes, historyRes, assignmentRes] = await Promise.all([
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
      } catch {
        setUsers([]);
        setScanRows([]);
        setDesktopSessions([]);
        setGatewayHistory([]);
        setGroupProxyAssignment(null);
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
  }, [token]);

  const adminDepartment = user?.department || '';
  const adminGroup = user?.group_name || '';

  const realEmployees = useMemo(() => {
    if (!adminDepartment || !adminGroup) return [];
    return users.filter(
      (entry) =>
        !entry.is_admin &&
        entry.department === adminDepartment &&
        entry.group_name === adminGroup,
    );
  }, [adminDepartment, adminGroup, users]);

  const employeeSlots = useMemo<EmployeeSlot[]>(() => {
    const registered = realEmployees.map((entry) => ({
      key: `user-${entry.id}`,
      id: entry.id,
      name: formatName(entry),
      email: entry.email,
      sex: entry.sex || null,
      department: entry.department || adminDepartment,
      group_name: entry.group_name || adminGroup,
      joinedAt: entry.created_at,
      state: 'registered' as const,
    }));

    const missing = Math.max(0, EXPECTED_GROUP_EMPLOYEES - registered.length);
    const placeholders = Array.from({ length: missing }, (_, index) => ({
      key: `placeholder-${index + 1}`,
      id: null,
      name: `Employee Slot ${index + 1}`,
      email: null,
      sex: null,
      department: adminDepartment,
      group_name: adminGroup,
      joinedAt: null,
      state: 'placeholder' as const,
    }));

    return [...registered, ...placeholders];
  }, [adminDepartment, adminGroup, realEmployees]);

  const employeeIds = useMemo(
    () => new Set(realEmployees.map((entry) => entry.id)),
    [realEmployees],
  );

  const groupScans = useMemo(
    () => scanRows.filter((row) => row.user_id && employeeIds.has(row.user_id)),
    [scanRows, employeeIds],
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

  const onlineEmployees = useMemo(
    () => realEmployees.filter((entry) => latestSessionByUser.get(entry.id)?.online).length,
    [latestSessionByUser, realEmployees],
  );

  const suspiciousCount = useMemo(
    () =>
      groupScans.filter(
        (row) => row.status === 'suspicious' || row.status === 'malicious',
      ).length,
    [groupScans],
  );

  const latestActivity = useMemo(() => {
    const latest = groupScans[0]?.created_at || null;
    return formatDateTime(latest);
  }, [groupScans]);

  const recentScans = useMemo(() => groupScans.slice(0, 5), [groupScans]);

  const tabs: { id: MonitoringTab; label: string; icon: typeof Activity }[] = [
    { id: 'overview', label: translateText('Overview'), icon: Activity },
    { id: 'employees', label: translateText('Employees'), icon: Users },
    { id: 'sessions', label: 'Session Presence', icon: Briefcase },
  ];

  return (
    <div className="gateway-start global-scroll flex-1 bg-slate-900">
      <div className="space-y-6 p-8">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="mb-2 text-3xl font-bold text-white">{translateText('Monitoring')}</h2>
            <p className="text-slate-400">
              Real group-based monitoring for the current admin scope.
            </p>
          </div>
          <div className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-2 text-sm text-cyan-300">
            {adminDepartment && adminGroup
              ? `${adminDepartment} · ${adminGroup}`
              : 'Missing admin scope'}
          </div>
        </div>

        {!adminDepartment || !adminGroup ? (
          <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-5 text-amber-200">
            The current admin account does not have a department/group scope yet. Monitoring needs
            both values to build the employee view.
          </div>
        ) : null}

        <div className="grid grid-cols-1 gap-4 md:grid-cols-5">
          <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-4">
            <div className="mb-2 flex items-center justify-between">
              <p className="text-sm text-slate-400">Expected Employees</p>
              <Users className="h-5 w-5 text-cyan-400" />
            </div>
            <p className="text-3xl font-bold text-white">{EXPECTED_GROUP_EMPLOYEES}</p>
          </div>
          <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-4">
            <div className="mb-2 flex items-center justify-between">
              <p className="text-sm text-slate-400">Registered Employees</p>
              <UserCheck className="h-5 w-5 text-emerald-400" />
            </div>
            <p className="text-3xl font-bold text-white">{realEmployees.length}</p>
          </div>
          <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-4">
            <div className="mb-2 flex items-center justify-between">
              <p className="text-sm text-slate-400">Open Slots</p>
              <UserPlus className="h-5 w-5 text-amber-400" />
            </div>
            <p className="text-3xl font-bold text-white">
              {Math.max(0, EXPECTED_GROUP_EMPLOYEES - realEmployees.length)}
            </p>
          </div>
          <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-4">
            <div className="mb-2 flex items-center justify-between">
              <p className="text-sm text-slate-400">Online Employees</p>
              <Activity className="h-5 w-5 text-emerald-400" />
            </div>
            <p className="text-3xl font-bold text-white">{onlineEmployees}</p>
          </div>
          <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-4">
            <div className="mb-2 flex items-center justify-between">
              <p className="text-sm text-slate-400">Group Scans</p>
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
                  <h3 className="text-xl font-bold text-white">Group Overview</h3>
                  <p className="mt-1 text-sm text-slate-400">
                    Built from the employees registered in the current admin group.
                  </p>
                </div>
                {loading && <span className="text-sm text-slate-500">Loading...</span>}
              </div>

              <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                  <p className="text-sm text-slate-400">Latest Group Activity</p>
                  <p className="mt-3 text-lg font-semibold text-white">{latestActivity}</p>
                </div>
                <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                  <p className="text-sm text-slate-400">Suspicious or Malicious Scans</p>
                  <p className="mt-3 text-lg font-semibold text-amber-300">{suspiciousCount}</p>
                </div>
                <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                  <p className="text-sm text-slate-400">Registered vs Expected</p>
                  <p className="mt-3 text-lg font-semibold text-white">
                    {realEmployees.length} / {EXPECTED_GROUP_EMPLOYEES}
                  </p>
                </div>
              </div>

              <div className="mt-6">
                <h4 className="mb-3 text-lg font-semibold text-white">Employee Slots</h4>
                <div className="space-y-3">
                  {employeeSlots.map((entry) => {
                    const latestSession = entry.id ? latestSessionByUser.get(entry.id) : undefined;
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
                              <p className="mt-2 text-xs text-slate-500">
                                {latestSession.online
                                  ? `Connected from ${latestSession.hostname || latestSession.device_id || 'desktop'}`
                                  : `Last heartbeat ${formatDateTime(latestSession.last_heartbeat || null)}`}
                              </p>
                            ) : null}
                          </div>
                          <span
                            className={`rounded-full border px-3 py-1 text-xs font-semibold ${
                              entry.state !== 'registered'
                                ? 'border-slate-700 bg-slate-800/70 text-slate-400'
                                : latestSession?.online
                                  ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                                  : 'border-slate-700 bg-slate-800/70 text-slate-300'
                            }`}
                          >
                            {entry.state !== 'registered'
                              ? 'Placeholder'
                              : latestSession?.online
                                ? 'Online'
                                : 'Registered'}
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
                <div className="space-y-3">
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
                  No scans from the current group yet. Once group members start scanning, this panel
                  will populate automatically.
                </div>
              )}
            </div>
          </div>
        )}

        {activePanel === 'employees' && (
          <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-6">
            <h3 className="mb-5 text-xl font-bold text-white">Employees in Current Group</h3>
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              {employeeSlots.map((entry) => {
                const scanCount = entry.id ? scanCountByUser.get(entry.id) || 0 : 0;
                const latestSession = entry.id ? latestSessionByUser.get(entry.id) : undefined;
                return (
                  <div
                    key={entry.key}
                    className={`rounded-xl border p-5 ${
                      entry.state === 'registered'
                        ? 'border-slate-700 bg-slate-900/50'
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
                              : latestSession?.online
                                ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                                : 'border-slate-700 bg-slate-800/70 text-slate-300'
                          }`}
                        >
                          {entry.state !== 'registered'
                            ? 'Placeholder'
                            : latestSession?.online
                              ? 'Online'
                              : 'Offline'}
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
                          {latestSession?.hostname || 'No desktop session'}
                        </p>
                      </div>
                      <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                        <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Last heartbeat</p>
                        <p className="mt-2 text-sm font-medium text-slate-200">
                          {latestSession ? formatDateTime(latestSession.last_heartbeat || null) : 'No session yet'}
                        </p>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {activePanel === 'sessions' && (
          <div className="rounded-xl border border-slate-700 bg-slate-800/50 p-6">
            <div className="mb-5 flex items-center gap-2">
              <Briefcase className="h-5 w-5 text-cyan-300" />
              <h3 className="text-xl font-bold text-white">Desktop Session Presence</h3>
            </div>

            <div className="mb-5 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4 text-sm leading-6 text-slate-300">
              Presence is now based on explicit desktop heartbeats sent by the executable. A worker
              stays online while the app is still connected, even if no proxy traffic is flowing.
            </div>

            <div className="mb-5 grid grid-cols-1 gap-4 lg:grid-cols-[0.9fr_1.1fr]">
              <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Group Proxy Assignment</p>
                {groupProxyAssignment ? (
                  <>
                    <p className="mt-3 text-lg font-semibold text-white">
                      {groupProxyAssignment.proxy_host}:{groupProxyAssignment.proxy_port}
                    </p>
                    <p className="mt-1 text-sm text-slate-400">
                      {groupProxyAssignment.department} · {groupProxyAssignment.group_name}
                    </p>
                    <p className="mt-2 text-xs text-slate-500">
                      {groupProxyAssignment.note || 'Fixed group assignment ready for routed gateway mode.'}
                    </p>
                  </>
                ) : (
                  <p className="mt-3 text-sm text-slate-400">No fixed proxy assignment defined for this group yet.</p>
                )}
              </div>

              <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Recent Attached Gateway Usage</p>
                {gatewayHistory.length ? (
                  <div className="mt-3 space-y-3">
                    {gatewayHistory.slice(0, 4).map((event, index) => (
                      <div key={`${event.timestamp || 't'}-${index}`} className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <p className="truncate text-sm font-semibold text-white">{event.host || 'Unknown target'}</p>
                            <p className="mt-1 text-xs text-slate-400">
                              {(event.user_name || event.user_email || 'Unattached worker')} · {event.hostname || 'Unknown device'}
                            </p>
                          </div>
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
                        <p className="mt-2 text-xs text-slate-500">
                          {(event.method || 'HTTP').toUpperCase()} · {formatDateTime(event.timestamp || null)}
                        </p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="mt-3 text-sm text-slate-400">
                    No attached gateway events yet. Once workers use the proxy, events will appear here under the active desktop session.
                  </p>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              {desktopSessions.length ? desktopSessions.map((session) => (
                <div key={session.session_id} className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-white">{session.user_name}</p>
                      <p className="mt-1 text-xs text-slate-400">{session.email}</p>
                    </div>
                    <span
                      className={`rounded-full border px-3 py-1 text-xs font-semibold ${
                        session.online
                          ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                          : 'border-slate-700 bg-slate-800/70 text-slate-300'
                      }`}
                    >
                      {session.online ? 'Online' : 'Offline'}
                    </span>
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
                  </div>
                </div>
              )) : (
                <div className="rounded-xl border border-dashed border-slate-700 bg-slate-950/35 p-5 text-sm text-slate-400">
                  No desktop sessions detected yet for the current group. Once workers open the
                  executable and authenticate, their presence will appear here automatically.
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

