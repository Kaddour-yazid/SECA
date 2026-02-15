import { Shield, FileText, Globe, Hash, LayoutDashboard, ScrollText, LogOut, Sun, Moon, User } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useTheme } from '../contexts/ThemeContext';

type SidebarProps = {
  activeView: string;
  onViewChange: (view: string) => void;
};

export function Sidebar({ activeView, onViewChange }: SidebarProps) {
  const { user, signOut } = useAuth();
  const { theme, toggleTheme } = useTheme();

  // Base menu items (available to all users)
  const baseMenuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'file', label: 'File Scanner', icon: FileText },
    { id: 'url', label: 'URL Scanner', icon: Globe },
    { id: 'hash', label: 'Hash Checker', icon: Hash },
  ];

  // Admin-only menu items
  const adminMenuItems = [
    { id: 'audit', label: 'Audit Logs', icon: ScrollText },
  ];

  // Combine menu items based on user role
  const menuItems = user?.is_admin
    ? [...baseMenuItems, ...adminMenuItems]
    : baseMenuItems;

  return (
    <div className="w-64 bg-slate-800 light:bg-white dark:bg-slate-800 border-r border-slate-700 light:border-slate-200 flex flex-col">
      {/* Logo */}
      <div className="p-6 border-b border-slate-700">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-lg flex items-center justify-center">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-white font-bold text-lg">SECA</h1>
            <p className="text-slate-400 text-xs">Security Analyzer</p>
          </div>
        </div>
      </div>

      {/* User Info */}
      <div className="p-4 border-b border-slate-700">
        <div className="flex items-center gap-3 px-2 py-2 bg-slate-900/50 rounded-lg">
          <div className="w-8 h-8 bg-cyan-500/20 rounded-full flex items-center justify-center">
            <User className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-white text-sm font-medium truncate">{user?.email}</p>
            <p className="text-slate-400 text-xs">
              {user?.is_admin ? (
                <span className="text-cyan-400 font-medium">Admin</span>
              ) : (
                'User'
              )}
            </p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeView === item.id;

          return (
            <button
              key={item.id}
              onClick={() => onViewChange(item.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
                isActive
                  ? 'bg-cyan-500 text-white shadow-lg'
                  : 'text-slate-300 bg-transparent hover:bg-cyan-500/10 hover:text-cyan-400'
              }`}
            >
              <Icon className="w-5 h-5" />
              <span className="font-medium">{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Theme Toggle & Logout */}
      <div className="p-4 border-t border-slate-700 space-y-2">
        <button
          onClick={toggleTheme}
          className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-slate-300 hover:bg-slate-700 hover:text-white transition"
        >
          {theme === 'dark' ? (
            <>
              <Sun className="w-5 h-5" />
              <span className="font-medium">Light Mode</span>
            </>
          ) : (
            <>
              <Moon className="w-5 h-5" />
              <span className="font-medium">Dark Mode</span>
            </>
          )}
        </button>

        <button
          onClick={signOut}
          className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-red-400 hover:bg-red-500/10 hover:text-red-300 transition"
        >
          <LogOut className="w-5 h-5" />
          <span className="font-medium">Sign Out</span>
        </button>
      </div>
    </div>
  );
}