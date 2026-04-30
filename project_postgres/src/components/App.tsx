import { useEffect, useRef, useState } from 'react';
import { LogOut, Mail, Settings, Shield } from 'lucide-react';
import { AuthProvider, useAuth } from '../contexts/AuthContext';
import { LanguageProvider, useLanguage } from '../contexts/LanguageContext';
import { ThemeProvider } from '../contexts/ThemeContext';
import { LoginView } from './LoginView';
import { DashboardView } from './DashboardView';
import { FileScannerView } from './FileScannerView';
import { URLScannerView } from './URLScannerView';
import { EmailScannerView } from './EmailScannerView';
import { HashCheckerView } from './HashCheckerView';
import { AuditLogsView } from './AuditLogsView';
import { GatewayStartView } from './GatewayStartView';
import { AccessControlView } from './AccessControlView';
import { ParametersView } from './ParametersView';
import { PoliciesView } from './PoliciesView';
import { Sidebar } from './Sidebar';

function TopStrip({ onViewChange }: { onViewChange: (view: string) => void }) {
  const { user, signOut } = useAuth();
  const { translateText } = useLanguage();
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  const profileRef = useRef<HTMLDivElement | null>(null);

  const canAdmin = Boolean(user?.is_admin);
  const firstName = user?.first_name || '';
  const lastName = user?.last_name || '';
  const displayName = [firstName, lastName].filter(Boolean).join(' ') || user?.email || 'SECA User';
  const compactName = [firstName, lastName ? `${lastName.charAt(0)}.` : ''].filter(Boolean).join(' ') || displayName;
  const roleLabel = user?.admin_department ? 'Admin departement' : user?.admin_group ? 'Admin groupe' : user?.is_admin ? 'Admin' : 'Analyste';
  const initials = `${firstName.charAt(0)}${lastName.charAt(0)}`.trim().toUpperCase() || user?.email?.charAt(0)?.toUpperCase() || 'S';
  const departmentLabel = user?.department || 'Departement non defini';
  const groupLabel = user?.group_name || 'Groupe non defini';

  useEffect(() => {
    if (!isProfileOpen) {
      return;
    }

    const handlePointerDown = (event: MouseEvent) => {
      if (profileRef.current && !profileRef.current.contains(event.target as Node)) {
        setIsProfileOpen(false);
      }
    };

    document.addEventListener('mousedown', handlePointerDown);
    return () => document.removeEventListener('mousedown', handlePointerDown);
  }, [isProfileOpen]);

  return (
    <header dir="ltr" className="relative z-40 h-[88px] shrink-0 border-b border-slate-700/90 bg-slate-900/95 backdrop-blur-sm">
      <div className="flex h-full items-center justify-between px-8">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600">
            <Shield className="h-6 w-6 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white">SECA</h1>
            <p className="text-xs text-slate-400">{translateText('Security Analyzer')}</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="h-8 w-px bg-white/10" />
          <div ref={profileRef} className="relative">
            <button
              type="button"
              onClick={() => setIsProfileOpen(prev => !prev)}
              className="group flex items-center gap-3 rounded-xl px-2 py-2 transition hover:bg-slate-800/60"
            >
              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-gradient-to-br from-blue-500 to-blue-700 text-sm font-semibold text-white">
                {initials}
              </div>
              <div className="min-w-0 text-left">
                <p className="max-w-[160px] truncate text-sm font-semibold text-white">{compactName}</p>
                <p className="text-xs text-slate-400">{roleLabel}</p>
              </div>
              <svg
                className={`h-4 w-4 text-slate-500 transition duration-200 group-hover:text-slate-300 ${isProfileOpen ? 'rotate-180' : ''}`}
                viewBox="0 0 20 20"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path d="M6 8L10 12L14 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </button>

            {isProfileOpen && (
              <div className="absolute right-0 top-full z-30 mt-3 w-80 max-w-[calc(100vw-2rem)] overflow-hidden rounded-2xl border border-slate-700/80 bg-slate-900 text-left shadow-2xl shadow-slate-950/60">
                <div className="border-b border-slate-800/90 bg-slate-900 px-5 py-4">
                  <div className="flex items-start gap-3">
                    <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-blue-500 to-blue-700 text-sm font-semibold text-white">
                      {initials}
                    </div>
                    <div className="min-w-0">
                      <p className="truncate text-sm font-semibold text-white">{displayName}</p>
                      <div className="mt-1 flex items-center gap-2">
                        <span className="rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-emerald-300">
                          Session active
                        </span>
                        <span className="rounded-full border border-cyan-500/20 bg-cyan-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-cyan-300">
                          {roleLabel}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="space-y-3 px-5 py-4">
                  <div className="flex items-start gap-3 rounded-xl border border-slate-800/80 bg-slate-950/95 px-3 py-3">
                    <Mail className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" />
                    <div className="min-w-0">
                      <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">E-mail</p>
                      <p className="truncate text-sm text-slate-200">{user?.email}</p>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div className="rounded-xl border border-slate-800/80 bg-slate-950/95 px-3 py-3">
                      <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">Departement</p>
                      <p className="mt-1 text-sm text-slate-200">{departmentLabel}</p>
                    </div>
                    <div className="rounded-xl border border-slate-800/80 bg-slate-950/95 px-3 py-3">
                      <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">Groupe</p>
                      <p className="mt-1 text-sm text-slate-200">{groupLabel}</p>
                    </div>
                  </div>

                  <div className="flex items-center justify-between rounded-xl border border-blue-500/15 bg-slate-950 px-3 py-3">
                    <div>
                      <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-blue-300/70">Acces</p>
                      <p className="mt-1 text-sm font-medium text-blue-100">
                        {user?.admin_department
                          ? 'Supervision et administration du departement'
                          : user?.admin_group
                            ? 'Supervision et administration du groupe'
                            : canAdmin
                              ? 'Supervision securisee'
                              : 'Analyse et consultation securisee'}
                      </p>
                    </div>
                    <Shield className="h-5 w-5 shrink-0 text-blue-300" />
                  </div>
                </div>

                <div className="border-t border-slate-800/90 px-3 py-3">
                  <button
                    type="button"
                    onClick={() => {
                      setIsProfileOpen(false);
                      onViewChange('settings');
                    }}
                    className="flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left text-sm text-slate-200 transition hover:bg-slate-800/70"
                  >
                    <Settings className="h-4 w-4 text-slate-400" />
                    Parametres du compte
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setIsProfileOpen(false);
                      signOut();
                    }}
                    className="mt-1 flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left text-sm text-rose-300 transition hover:bg-rose-500/10"
                  >
                    <LogOut className="h-4 w-4 text-rose-300" />
                    Deconnexion
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
}

function AppContent() {
  const { user } = useAuth();
  const { language } = useLanguage();
  const [activeView, setActiveView] = useState('dashboard');

  if (!user) {
    return <LoginView />;
  }

  const handleViewChange = (view: string) => {
    if (view === 'start' && !user?.is_admin) {
      setActiveView('dashboard');
      return;
    }
    if (view === 'audit' && !user?.is_admin) {
      setActiveView('dashboard');
      return;
    }
    if (view === 'access-control' && !user?.is_admin) {
      setActiveView('dashboard');
      return;
    }
    setActiveView(view);
  };

  return (
    <div key={language} className="relative isolate flex h-screen flex-col overflow-hidden bg-slate-950 dark:bg-slate-950">
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="absolute -left-28 top-20 h-80 w-80 rounded-full bg-cyan-500/10 blur-3xl" />
        <div className="absolute right-[-8rem] top-28 h-[26rem] w-[26rem] rounded-full bg-blue-500/10 blur-3xl" />
        <div className="absolute bottom-[-10rem] left-1/3 h-96 w-96 rounded-full bg-sky-400/10 blur-3xl" />
        <div className="absolute inset-x-0 top-0 h-56 bg-[radial-gradient(circle_at_top,rgba(59,130,246,0.10),transparent_62%)]" />
      </div>

      <TopStrip onViewChange={handleViewChange} />

      <div className="flex min-h-0 flex-1 overflow-hidden">
        <Sidebar activeView={activeView} onViewChange={handleViewChange} />
        <main className="relative z-0 min-h-0 flex-1 overflow-hidden">
          <div className={activeView === 'dashboard' ? 'h-full' : 'hidden h-full'}>
            <DashboardView isActive={activeView === 'dashboard'} />
          </div>
          <div className={activeView === 'file' ? 'h-full' : 'hidden h-full'}>
            <FileScannerView />
          </div>
          <div className={activeView === 'url' ? 'h-full' : 'hidden h-full'}>
            <URLScannerView />
          </div>
          <div className={activeView === 'email' ? 'h-full' : 'hidden h-full'}>
            <EmailScannerView />
          </div>
          <div className={activeView === 'hash' ? 'h-full' : 'hidden h-full'}>
            <HashCheckerView />
          </div>
          {user?.is_admin && (
            <div className={activeView === 'start' ? 'h-full' : 'hidden h-full'}>
              <GatewayStartView />
            </div>
          )}
          {user?.is_admin && (
            <div className={activeView === 'audit' ? 'h-full' : 'hidden h-full'}>
              <AuditLogsView />
            </div>
          )}
          {user?.is_admin && (
            <div className={activeView === 'access-control' ? 'h-full' : 'hidden h-full'}>
              <AccessControlView />
            </div>
          )}
          <div className={activeView === 'policies' ? 'h-full' : 'hidden h-full'}>
            <PoliciesView />
          </div>
          <div className={activeView === 'settings' ? 'h-full' : 'hidden h-full'}>
            <ParametersView />
          </div>
        </main>
      </div>
    </div>
  );
}

export function App() {
  return (
    <LanguageProvider>
      <ThemeProvider>
        <AuthProvider>
          <AppContent />
        </AuthProvider>
      </ThemeProvider>
    </LanguageProvider>
  );
}

export default App;
