import { useState } from 'react';
import { AuthProvider, useAuth } from '../contexts/AuthContext';
import { ThemeProvider } from '../contexts/ThemeContext';
import { LoginView } from './LoginView';
import { DashboardView } from './DashboardView';
import { FileScannerView } from './FileScannerView';
import { URLScannerView } from './URLScannerView';
import { HashCheckerView } from './HashCheckerView';
import { AuditLogsView } from './AuditLogsView';
import { GatewayStartView } from './GatewayStartView';
import { AccessControlView } from './AccessControlView';
import { Sidebar } from './Sidebar';

function AppContent() {
  const { user } = useAuth();
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
    <div className="flex h-screen bg-slate-900 dark:bg-slate-900">
      <Sidebar activeView={activeView} onViewChange={handleViewChange} />
      <main className="flex-1 overflow-hidden">
        <div className={activeView === 'dashboard' ? 'h-full' : 'hidden h-full'}>
          <DashboardView />
        </div>
        <div className={activeView === 'file' ? 'h-full' : 'hidden h-full'}>
          <FileScannerView />
        </div>
        <div className={activeView === 'url' ? 'h-full' : 'hidden h-full'}>
          <URLScannerView />
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
      </main>
    </div>
  );
}

export function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </ThemeProvider>
  );
}

// Default export for compatibility
export default App;
