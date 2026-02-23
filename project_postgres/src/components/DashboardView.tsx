import { useEffect, useState } from "react";
import { Activity, Shield, AlertTriangle, CheckCircle } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

export function DashboardView() {
  const { token } = useAuth();
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState({
    total: 0,
    clean: 0,
    malicious: 0,
    suspicious: 0,
  });

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);

      if (!token) {
        throw new Error('No authentication token');
      }

      const res = await fetch("http://127.0.0.1:8000/scans", {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!res.ok) {
        throw new Error('Failed to fetch dashboard data');
      }
      const data = await res.json();
      setScans(data);

      const total = data.length;
      const clean = data.filter((s: any) => s.status === 'clean').length;
      const malicious = data.filter((s: any) => s.status === 'malicious').length;
      const suspicious = data.filter((s: any) => s.status === 'suspicious').length;

      setStats({ total, clean, malicious, suspicious });
      setError(null);
    } catch (err) {
      console.error("Failed to load dashboard data:", err);
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex-1 bg-slate-900 global-scroll">
      <div className="p-8">
        <h2 className="text-3xl font-bold text-white mb-2">Dashboard</h2>
        <p className="text-slate-400 mb-8">Overview of your security scans</p>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-slate-400 text-sm font-medium">Total Scans</h3>
              <Activity className="w-5 h-5 text-cyan-400" />
            </div>
            <p className="text-3xl font-bold text-white">{stats.total}</p>
          </div>

          <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-6">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-green-400 text-sm font-medium">Clean</h3>
              <CheckCircle className="w-5 h-5 text-green-400" />
            </div>
            <p className="text-3xl font-bold text-green-400">{stats.clean}</p>
          </div>

          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-6">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-red-400 text-sm font-medium">Malicious</h3>
              <Shield className="w-5 h-5 text-red-400" />
            </div>
            <p className="text-3xl font-bold text-red-400">{stats.malicious}</p>
          </div>

          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-6">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-yellow-400 text-sm font-medium">Suspicious</h3>
              <AlertTriangle className="w-5 h-5 text-yellow-400" />
            </div>
            <p className="text-3xl font-bold text-yellow-400">{stats.suspicious}</p>
          </div>
        </div>

        {/* Recent Scans */}
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4">Recent Scans</h3>

          {loading && (
            <div className="text-center py-8">
              <div className="w-12 h-12 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
              <p className="text-slate-400">Loading scans...</p>
            </div>
          )}

          {error && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
              <p className="text-red-400">{error}</p>
            </div>
          )}

          {!loading && !error && scans.length === 0 && (
            <p className="text-slate-400 text-center py-8">No scans yet</p>
          )}

          {!loading && !error && scans.length > 0 && (
            <ul className="space-y-3">
              {scans.slice(0, 10).map((scan, i) => (
                <li
                  key={i}
                  className="flex items-center justify-between p-4 bg-slate-900/50 rounded-lg border border-slate-700 hover:border-slate-600 transition"
                >
                  <div className="flex items-center gap-4">
                    <div className={`w-2 h-2 rounded-full ${
                      scan.status === 'clean' ? 'bg-green-400' :
                      scan.status === 'malicious' ? 'bg-red-400' :
                      'bg-yellow-400'
                    }`} />
                    <div>
                      <p className="text-white font-medium">{scan.target || 'N/A'}</p>
                      <p className="text-slate-400 text-sm">{scan.scan_type || 'Unknown'}</p>
                    </div>
                  </div>
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                    scan.status === 'clean' ? 'bg-green-500/10 text-green-400 border border-green-500/30' :
                    scan.status === 'malicious' ? 'bg-red-500/10 text-red-400 border border-red-500/30' :
                    'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30'
                  }`}>
                    {scan.status || 'Unknown'}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}