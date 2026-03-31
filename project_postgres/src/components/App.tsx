import { useState } from 'react';
import { AuthProvider, useAuth } from '../contexts/AuthContext';
import { LanguageProvider, useLanguage } from '../contexts/LanguageContext';
import { ThemeProvider } from '../contexts/ThemeContext';
import { LoginView } from './LoginView';
import { DashboardView } from './DashboardView';
import { FileScannerView } from './FileScannerView';
import { URLScannerView } from './URLScannerView';
import { HashCheckerView } from './HashCheckerView';
import { AuditLogsView } from './AuditLogsView';
import { GatewayStartView } from './GatewayStartView';
import { AccessControlView } from './AccessControlView';
import { ParametersView } from './ParametersView';
import { Sidebar } from './Sidebar';

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
    <div key={language} className="flex h-screen min-h-0 bg-slate-900 dark:bg-slate-900">
      <Sidebar activeView={activeView} onViewChange={handleViewChange} />
      <main className="global-scroll visible-scrollbar relative flex-1 min-w-0 overflow-x-hidden overflow-y-auto">
        <div className={activeView === 'dashboard' ? 'h-full min-h-0' : 'hidden h-full min-h-0'}>
          <DashboardView isActive={activeView === 'dashboard'} />
        </div>
        <div className={activeView === 'file' ? 'h-full min-h-0' : 'hidden h-full min-h-0'}>
          <FileScannerView />
        </div>
        <div className={activeView === 'url' ? 'h-full min-h-0' : 'hidden h-full min-h-0'}>
          <URLScannerView />
        </div>
        <div className={activeView === 'hash' ? 'h-full min-h-0' : 'hidden h-full min-h-0'}>
          <HashCheckerView />
        </div>
        {user?.is_admin && (
          <div className={activeView === 'start' ? 'h-full min-h-0' : 'hidden h-full min-h-0'}>
            <GatewayStartView />
          </div>
        )}
        {user?.is_admin && (
          <div className={activeView === 'audit' ? 'h-full min-h-0' : 'hidden h-full min-h-0'}>
            <AuditLogsView />
          </div>
        )}
        {user?.is_admin && (
          <div className={activeView === 'access-control' ? 'h-full min-h-0' : 'hidden h-full min-h-0'}>
            <AccessControlView />
          </div>
        )}
        <div className={activeView === 'settings' ? 'h-full min-h-0' : 'hidden h-full min-h-0'}>
          <ParametersView />
        </div>
      </main>
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

// Default export for compatibility
export default App;
