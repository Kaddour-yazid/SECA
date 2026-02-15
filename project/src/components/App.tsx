import { useState } from 'react';
import { AuthProvider, useAuth } from '../contexts/AuthContext';
import { ThemeProvider } from '../contexts/ThemeContext';
import { LoginView } from './LoginView';
import { DashboardView } from './DashboardView';
import { FileScannerView } from './FileScannerView';
import { URLScannerView } from './URLScannerView';
import { HashCheckerView } from './HashCheckerView';
import { AuditLogsView } from './AuditLogsView';
import { Sidebar } from './Sidebar';

function AppContent() {
  const { user } = useAuth();
  const [activeView, setActiveView] = useState('dashboard');

  if (!user) {
    return <LoginView />;
  }

  const renderView = () => {
    switch (activeView) {
      case 'dashboard':
        return <DashboardView />;
      case 'file':
        return <FileScannerView />;
      case 'url':
        return <URLScannerView />;
      case 'hash':
        return <HashCheckerView />;
      case 'audit':
        return <AuditLogsView />;
      default:
        return <DashboardView />;
    }
  };

  return (
    <div className="flex h-screen bg-slate-900 dark:bg-slate-900">
      <Sidebar activeView={activeView} onViewChange={setActiveView} />
      <main className="flex-1 overflow-hidden">
        {renderView()}
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