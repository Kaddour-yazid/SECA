import { useEffect, useMemo, useState } from "react";
import { ArrowLeft, Download, Eye, Filter, Laptop, Search, Server, ShieldAlert } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { apiUrl } from "../config/api";

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
  connected?: boolean;
  activity_online?: boolean;
  activity_offline?: boolean;
  activity_timeout_seconds?: number;
  seconds_since_last_activity?: number | null;
  total_requests: number;
  blocked_requests: number;
  allowed_requests: number;
  last_seen: string;
};

type ProxyStats = {
  total_events: number;
  blocked_requests: number;
  allowed_requests: number;
};

type VerdictFilter = "all" | "blocked" | "allowed";

function tsvCell(value: unknown): string {
  const normalized = String(value ?? "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .replace(/\t/g, " ")
    .replace(/\n/g, "\\n")
    .replace(/"/g, "\"\"");
  return `"${normalized}"`;
}

function exportRows(rows: AuditLog[], filenamePrefix: string) {
  const headers = ["ID", "User", "User Email", "Action", "Details (Full)", "Timestamp"];
  const body = rows.map((r) =>
    [
      r.id,
      r.user_name || (r.user_id === null ? "System" : `User #${r.user_id}`),
      r.user_email || "",
      r.action,
      r.details,
      formatTimestamp(r.timestamp),
    ]
      .map(tsvCell)
      .join("\t")
  );
  const content = [headers.map(tsvCell).join("\t"), ...body].join("\n");
  const blob = new Blob([content], { type: "application/vnd.ms-excel;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${filenamePrefix}_${new Date().toISOString().split("T")[0]}.xls`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function formatSeconds(seconds?: number | null): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds) || seconds < 0) return "-";
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}m ${s}s`;
}

function parseBackendTimestamp(value?: string | null): Date | null {
  if (!value) return null;
  const normalized = /(?:Z|[+-]\d{2}:\d{2})$/i.test(value) ? value : `${value}Z`;
  const parsed = new Date(normalized);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function formatTimestamp(value?: string | null): string {
  const parsed = parseBackendTimestamp(value);
  if (!parsed) return "Unknown";
  return parsed.toLocaleString();
}

function localDateValue(value?: string | null): string {
  const parsed = parseBackendTimestamp(value);
  if (!parsed) return "";
  const year = parsed.getFullYear();
  const month = String(parsed.getMonth() + 1).padStart(2, "0");
  const day = String(parsed.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function logVerdict(log: AuditLog): VerdictFilter | "other" {
  const action = log.action.toLowerCase();
  const details = log.details.toLowerCase();
  if (action.includes("block") || details.includes("blocked")) return "blocked";
  if (action.includes("allow") || details.includes("allowed")) return "allowed";
  return "other";
}

export function AuditLogsView() {
  const { token } = useAuth();
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [gatewayError, setGatewayError] = useState<string | null>(null);
  const [health, setHealth] = useState<ProxyHealth | null>(null);
  const [devices, setDevices] = useState<ProxyDevice[]>([]);
  const [stats, setStats] = useState<ProxyStats | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [actionFilter, setActionFilter] = useState("all");
  const [verdictFilter, setVerdictFilter] = useState<VerdictFilter>("all");
  const [dateFilter, setDateFilter] = useState("");
  const [showDevicesPage, setShowDevicesPage] = useState(false);
  const [selectedDeviceIp, setSelectedDeviceIp] = useState<string | null>(null);
  const [deviceLogs, setDeviceLogs] = useState<AuditLog[]>([]);
  const [detailsLog, setDetailsLog] = useState<AuditLog | null>(null);

  const loadAuditLogs = async (showLoader: boolean) => {
    if (!token) return;
    try {
      if (showLoader) setLoading(true);
      const res = await fetch(apiUrl("/audit?sort_by=date&order=desc&limit=500"), {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error("Failed to fetch audit logs");
      setLogs((await res.json()) as AuditLog[]);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to fetch logs");
    } finally {
      if (showLoader) setLoading(false);
    }
  };

  const loadGatewayData = async () => {
    if (!token) return;
    try {
      const [h, d, s] = await Promise.all([
        fetch(apiUrl("/gateway/proxy/health"), { headers: { Authorization: `Bearer ${token}` } }),
        fetch(apiUrl("/gateway/api/devices"), { headers: { Authorization: `Bearer ${token}` } }),
        fetch(apiUrl("/gateway/api/stats"), { headers: { Authorization: `Bearer ${token}` } }),
      ]);
      if (!h.ok || !d.ok || !s.ok) throw new Error("Failed to fetch gateway telemetry");
      setHealth((await h.json()) as ProxyHealth);
      setDevices((await d.json()) as ProxyDevice[]);
      setStats((await s.json()) as ProxyStats);
      setGatewayError(null);
    } catch (e) {
      setGatewayError(e instanceof Error ? e.message : "Failed to fetch gateway telemetry");
    }
  };

  const loadDeviceLogs = async (clientIp: string) => {
    if (!token) return;
    const res = await fetch(apiUrl(`/gateway/api/device-logs/${encodeURIComponent(clientIp)}?limit=500`), {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.ok) {
      setDeviceLogs((await res.json()) as AuditLog[]);
    }
  };

  useEffect(() => {
    void loadAuditLogs(true);
    void loadGatewayData();
  }, [token]);

  useEffect(() => {
    if (!token) return;
    const id = window.setInterval(() => {
      void loadAuditLogs(false);
      void loadGatewayData();
    }, 3000);
    return () => window.clearInterval(id);
  }, [token]);

  useEffect(() => {
    if (!showDevicesPage) return;
    if (!selectedDeviceIp || !devices.some((d) => d.client_ip === selectedDeviceIp)) {
      setSelectedDeviceIp(devices[0]?.client_ip || null);
    }
  }, [showDevicesPage, selectedDeviceIp, devices]);

  useEffect(() => {
    if (!showDevicesPage || !selectedDeviceIp) return;
    void loadDeviceLogs(selectedDeviceIp);
    const id = window.setInterval(() => void loadDeviceLogs(selectedDeviceIp), 3000);
    return () => window.clearInterval(id);
  }, [showDevicesPage, selectedDeviceIp]);

  const filteredLogs = useMemo(() => {
    return logs.filter((l) => {
      if (actionFilter !== "all" && l.action !== actionFilter) return false;
      if (verdictFilter !== "all" && logVerdict(l) !== verdictFilter) return false;
      if (dateFilter && localDateValue(l.timestamp) !== dateFilter) return false;
      if (!searchTerm) return true;
      const s = searchTerm.toLowerCase();
      return (
        l.action.toLowerCase().includes(s) ||
        l.details.toLowerCase().includes(s) ||
        (l.user_name || "").toLowerCase().includes(s) ||
        (l.user_email || "").toLowerCase().includes(s) ||
        String(l.user_id ?? "").includes(s) ||
        formatTimestamp(l.timestamp).toLowerCase().includes(s)
      );
    });
  }, [logs, actionFilter, verdictFilter, dateFilter, searchTerm]);

  const uniqueActions = useMemo(() => Array.from(new Set(logs.map((l) => l.action))), [logs]);
  const selectedDevice = useMemo(() => devices.find((d) => d.client_ip === selectedDeviceIp) || null, [devices, selectedDeviceIp]);
  const detailsModal = detailsLog ? (
    <div className="fixed inset-0 bg-black/60 z-50 p-4 flex items-center justify-center" onClick={() => setDetailsLog(null)}>
      <div className="max-w-3xl w-full bg-slate-900 border border-slate-700 rounded-xl p-5" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between gap-3 mb-3">
          <div>
            <h3 className="text-white font-semibold">Log Details</h3>
            <p className="text-slate-400 text-xs">{detailsLog.action} | {formatTimestamp(detailsLog.timestamp)}</p>
          </div>
          <button className="text-slate-400 hover:text-white text-sm" onClick={() => setDetailsLog(null)}>Close</button>
        </div>
        <pre className="text-slate-200 text-sm whitespace-pre-wrap break-words bg-slate-950/60 border border-slate-700 rounded-lg p-3 max-h-[60vh] overflow-auto">{detailsLog.details}</pre>
      </div>
    </div>
  ) : null;

  if (showDevicesPage) {
    return (
      <div className="flex-1 bg-slate-900 global-scroll p-8 space-y-6">
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <button onClick={() => setShowDevicesPage(false)} className="px-3 py-2 rounded-lg border border-slate-600 text-slate-200 hover:bg-slate-800 flex items-center gap-2">
              <ArrowLeft className="w-4 h-4" />
              Back
            </button>
            <div>
              <h2 className="text-3xl font-bold text-white">Devices</h2>
              <p className="text-slate-400">Click a device to show its logs.</p>
            </div>
          </div>
          <button onClick={() => exportRows(deviceLogs, `device_logs_${selectedDeviceIp || "all"}`)} disabled={deviceLogs.length === 0} className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-lg flex items-center gap-2 disabled:opacity-50">
            <Download className="w-4 h-4" />
            Export Device Logs
          </button>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4 max-h-[75vh] overflow-y-auto space-y-2">
            {devices.length === 0 ? (
              <div className="rounded-lg border border-dashed border-slate-700 bg-slate-900/50 p-5 text-center">
                <p className="text-slate-200 font-medium">No connected devices</p>
                <p className="text-slate-400 text-sm mt-1">When a device starts using the proxy, it will appear here.</p>
              </div>
            ) : (
              devices.map((d) => (
                <button key={d.client_ip} onClick={() => setSelectedDeviceIp(d.client_ip)} className={`w-full text-left p-3 rounded-lg border ${selectedDeviceIp === d.client_ip ? "border-cyan-500 bg-cyan-500/10" : "border-slate-700 bg-slate-900/60"}`}>
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-slate-100 font-medium">{d.device_name}</p>
                    <div className="flex items-center gap-2 flex-wrap justify-end">
                      <span className={`text-[11px] px-2 py-0.5 rounded-full border ${d.connected ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/30" : "bg-amber-500/15 text-amber-300 border-amber-500/30"}`}>
                        {d.connected ? "Connected" : "Disconnected"}
                      </span>
                      <span className={`text-[11px] px-2 py-0.5 rounded-full border ${d.activity_offline ? "bg-rose-500/15 text-rose-300 border-rose-500/30" : "bg-cyan-500/15 text-cyan-300 border-cyan-500/30"}`}>
                        {d.activity_offline ? `Offline > ${d.activity_timeout_seconds ?? 60}s` : "Active <= 60s"}
                      </span>
                    </div>
                  </div>
                  <p className="text-xs text-cyan-300 mt-1">{d.client_ip}</p>
                  <p className="text-xs text-slate-400">Last activity: {formatSeconds(d.seconds_since_last_activity)} ago</p>
                </button>
              ))
            )}
          </div>

          <div className="xl:col-span-2 bg-slate-800/50 border border-slate-700 rounded-xl p-4">
            {devices.length === 0 ? (
              <div className="h-full min-h-[260px] flex items-center justify-center text-center">
                <div>
                  <p className="text-slate-200 font-medium">No device details to display</p>
                  <p className="text-slate-400 text-sm mt-1">Connect a PC or phone to the proxy and come back here.</p>
                </div>
              </div>
            ) : !selectedDevice ? (
              <p className="text-slate-400">Select a device.</p>
            ) : (
              <>
                <p className="text-slate-200 font-semibold">{selectedDevice.device_name} ({selectedDevice.client_ip})</p>
                <p className="text-xs text-slate-400 mb-4">Last seen: {formatTimestamp(selectedDevice.last_seen)}</p>
                <div className="flex items-center gap-2 flex-wrap mb-4">
                  <span className={`text-[11px] px-2 py-0.5 rounded-full border ${selectedDevice.connected ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/30" : "bg-amber-500/15 text-amber-300 border-amber-500/30"}`}>
                    {selectedDevice.connected ? "Connected" : "Disconnected"}
                  </span>
                  <span className={`text-[11px] px-2 py-0.5 rounded-full border ${selectedDevice.activity_offline ? "bg-rose-500/15 text-rose-300 border-rose-500/30" : "bg-cyan-500/15 text-cyan-300 border-cyan-500/30"}`}>
                    {selectedDevice.activity_offline ? `Offline after ${selectedDevice.activity_timeout_seconds ?? 60}s idle` : "Activity online"}
                  </span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead className="bg-slate-900/50">
                      <tr>
                        <th className="px-4 py-2 text-left text-xs text-slate-400 uppercase">Timestamp</th>
                        <th className="px-4 py-2 text-left text-xs text-slate-400 uppercase">Action</th>
                        <th className="px-4 py-2 text-left text-xs text-slate-400 uppercase">Details</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-700">
                      {deviceLogs.length === 0 ? (
                        <tr>
                          <td colSpan={3} className="px-4 py-8 text-center text-slate-400">No logs yet for this device.</td>
                        </tr>
                      ) : (
                        deviceLogs.map((log) => (
                          <tr key={log.id}>
                            <td className="px-4 py-3 text-sm text-slate-300 whitespace-nowrap">{formatTimestamp(log.timestamp)}</td>
                            <td className="px-4 py-3 text-sm text-slate-200 whitespace-nowrap">{log.action}</td>
                            <td className="px-4 py-3 text-sm text-slate-300">
                              <div className="line-clamp-2 break-words">{log.details}</div>
                              <button onClick={() => setDetailsLog(log)} className="text-cyan-300 hover:text-cyan-200 text-xs inline-flex items-center gap-1 mt-1">
                                <Eye className="w-3 h-3" />
                                View full details
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </div>
        </div>
        {detailsModal}
      </div>
    );
  }

  return (
    <div className="flex-1 bg-slate-900 global-scroll p-8 space-y-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h2 className="text-3xl font-bold text-white">Audit Logs</h2>
          <p className="text-slate-400">Main audit view (devices moved to dedicated page).</p>
        </div>
        <button onClick={() => exportRows(filteredLogs, "audit_logs")} disabled={filteredLogs.length === 0} className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-lg flex items-center gap-2 disabled:opacity-50">
          <Download className="w-4 h-4" />
          Export Excel
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
          <div className="flex items-center gap-2 text-slate-400 text-sm mb-2"><Server className="w-4 h-4 text-cyan-400" />Proxy Status</div>
          <p className={`text-xl font-semibold ${health?.running ? "text-emerald-300" : "text-red-300"}`}>{health?.running ? "Running" : "Stopped"}</p>
          <p className="text-xs text-slate-500 mt-1">{health ? `${health.listen_host}:${health.listen_port}` : "No data"}</p>
        </div>

        <button onClick={() => setShowDevicesPage(true)} className="bg-slate-800/50 border border-slate-700 rounded-xl p-4 text-left hover:border-cyan-500/40 transition">
          <div className="flex items-center gap-2 text-slate-400 text-sm mb-2"><Laptop className="w-4 h-4 text-cyan-400" />Connected Devices</div>
          <p className="text-xl font-semibold text-slate-100">{health?.connected_devices ?? 0}</p>
          <p className="text-xs text-cyan-300 mt-1">Click to open devices page</p>
        </button>

        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
          <div className="flex items-center gap-2 text-slate-400 text-sm mb-2"><ShieldAlert className="w-4 h-4 text-cyan-400" />Block Rate</div>
          <p className="text-xl font-semibold text-slate-100">
            {stats ? Math.round((stats.blocked_requests / Math.max(1, stats.blocked_requests + stats.allowed_requests)) * 100) : 0}%
          </p>
        </div>

        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
          <div className="flex items-center gap-2 text-slate-400 text-sm mb-2"><Filter className="w-4 h-4 text-cyan-400" />Total Events</div>
          <p className="text-xl font-semibold text-slate-100">{stats?.total_events ?? health?.total_events ?? 0}</p>
        </div>
      </div>

      {gatewayError && <p className="text-amber-300 text-sm">{gatewayError}</p>}

      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} placeholder="Search action, details, user, timestamp" className="w-full pl-10 pr-4 py-2 bg-slate-900/50 border border-slate-600 rounded-lg text-white" />
          </div>
          <select value={actionFilter} onChange={(e) => setActionFilter(e.target.value)} className="px-4 py-2 bg-slate-900/50 border border-slate-600 rounded-lg text-white">
            <option value="all">All Actions</option>
            {uniqueActions.map((a) => <option key={a} value={a}>{a}</option>)}
          </select>
          <select value={verdictFilter} onChange={(e) => setVerdictFilter(e.target.value as VerdictFilter)} className="px-4 py-2 bg-slate-900/50 border border-slate-600 rounded-lg text-white">
            <option value="all">All Verdicts</option>
            <option value="blocked">Blocked</option>
            <option value="allowed">Allowed</option>
          </select>
          <input type="date" value={dateFilter} onChange={(e) => setDateFilter(e.target.value)} className="px-4 py-2 bg-slate-900/50 border border-slate-600 rounded-lg text-white" />
        </div>
      </div>

      <div className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden">
        {loading ? (
          <p className="text-slate-400 p-6">Loading logs...</p>
        ) : error ? (
          <p className="text-red-400 p-6">{error}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-900/50">
                <tr>
                  <th className="px-4 py-2 text-left text-xs text-slate-400 uppercase">Timestamp</th>
                  <th className="px-4 py-2 text-left text-xs text-slate-400 uppercase">Action</th>
                  <th className="px-4 py-2 text-left text-xs text-slate-400 uppercase">User</th>
                  <th className="px-4 py-2 text-left text-xs text-slate-400 uppercase">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {filteredLogs.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-4 py-8 text-center text-slate-400">No audit logs match the current filters.</td>
                  </tr>
                ) : (
                  filteredLogs.map((log) => (
                    <tr key={log.id}>
                      <td className="px-4 py-3 text-sm text-slate-300 whitespace-nowrap">{formatTimestamp(log.timestamp)}</td>
                      <td className="px-4 py-3 text-sm text-slate-200 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <span>{log.action}</span>
                          {logVerdict(log) !== "other" && (
                            <span className={`text-[11px] px-2 py-0.5 rounded-full border ${logVerdict(log) === "blocked" ? "bg-rose-500/15 text-rose-300 border-rose-500/30" : "bg-emerald-500/15 text-emerald-300 border-emerald-500/30"}`}>
                              {logVerdict(log) === "blocked" ? "Blocked" : "Allowed"}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm text-slate-300">{log.user_name || (log.user_id === null ? "System" : `User #${log.user_id}`)}</td>
                      <td className="px-4 py-3 text-sm text-slate-300">
                        <div className="line-clamp-2 break-words">{log.details}</div>
                        <button onClick={() => setDetailsLog(log)} className="text-cyan-300 hover:text-cyan-200 text-xs inline-flex items-center gap-1 mt-1">
                          <Eye className="w-3 h-3" />
                          View full details
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {detailsModal}
    </div>
  );
}
