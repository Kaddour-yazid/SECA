import { useCallback, useLayoutEffect, useRef, useState } from 'react';
import { Shield, FileText, Globe, Hash, LayoutDashboard, User, Network, Settings, ShieldBan, ScrollText } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useLanguage } from '../contexts/LanguageContext';
import { useTheme } from '../contexts/ThemeContext';

type SidebarProps = {
  activeView: string;
  onViewChange: (view: string) => void;
};

export function Sidebar({ activeView, onViewChange }: SidebarProps) {
  const { user } = useAuth();
  const { translateText } = useLanguage();
  const { theme } = useTheme();
  const navRef = useRef<HTMLElement | null>(null);
  const itemRefs = useRef<Record<string, HTMLButtonElement | null>>({});
  const [activeIndicator, setActiveIndicator] = useState({
    top: 0,
    height: 0,
    ready: false,
  });

  // Base menu items (available to all users)
  const baseMenuItems = [
    { id: 'dashboard', label: translateText('Dashboard'), icon: LayoutDashboard },
    { id: 'file', label: translateText('File Scanner'), icon: FileText },
    { id: 'url', label: translateText('URL Scanner'), icon: Globe },
    { id: 'hash', label: translateText('Hash Checker'), icon: Hash },
  ];

  // Admin-only menu items
  const adminMenuItems = [
    { id: 'start', label: translateText('Monitoring'), icon: Network },
    { id: 'audit', label: translateText('Audit Logs'), icon: ScrollText },
    { id: 'access-control', label: translateText('Access Control'), icon: ShieldBan },
  ];

  // Combine menu items based on user role
  const menuItems = user?.is_admin
    ? [...baseMenuItems, ...adminMenuItems]
    : baseMenuItems;

  const isLight = theme === 'light';
  const isFemale = (user?.sex || '').toLowerCase() === 'female';
  const userDisplayName = [user?.first_name, user?.last_name].filter(Boolean).join(' ') || user?.email || 'User';
  const sidebarShellClass = isLight
    ? 'w-64 bg-[#f8fbff] border-r border-[#d9e6f2] flex flex-col'
    : 'w-64 bg-slate-800 border-r border-slate-700 flex flex-col';
  const logoBorderClass = isLight ? 'border-b border-[#d9e6f2]' : 'border-b border-slate-700';
  const userBorderClass = isLight ? 'border-b border-[#d9e6f2]' : 'border-b border-slate-700';
  const userCardClass = isLight ? 'bg-white/90 border border-[#d9e6f2]' : 'bg-slate-900/50';
  const titleClass = isLight ? 'text-slate-900 font-bold text-lg' : 'text-white font-bold text-lg';
  const subtitleClass = isLight ? 'text-slate-500 text-xs' : 'text-slate-400 text-xs';
  const emailClass = isLight ? 'text-slate-900 text-sm font-medium truncate' : 'text-white text-sm font-medium truncate';
  const userRoleClass = isLight ? 'text-slate-500 text-xs' : 'text-slate-400 text-xs';
  const userCardToneClass = isLight
    ? isFemale
      ? 'border border-pink-200 bg-pink-50/90'
      : 'border border-[#d9e6f2] bg-white/90'
    : isFemale
      ? 'border border-pink-500/20 bg-pink-500/10'
      : 'bg-slate-900/50';
  const userIconToneClass = isFemale
    ? 'bg-pink-500/20 text-pink-300'
    : 'bg-cyan-500/20 text-cyan-400';
  const userNameClass = isLight ? 'text-slate-900 text-sm font-semibold truncate' : isFemale ? 'text-pink-100 text-sm font-semibold truncate' : 'text-white text-sm font-semibold truncate';
  const userMetaAccentClass = isFemale ? 'text-pink-300' : 'text-cyan-400';
  const navDefaultClass = isLight
    ? 'text-slate-700 bg-transparent hover:bg-sky-100 hover:text-sky-700'
    : 'text-slate-300 bg-transparent hover:bg-cyan-500/10 hover:text-cyan-400';
  const navActiveClass = isLight ? 'text-sky-900' : 'text-white';
  const navIndicatorClass = isLight
    ? 'pointer-events-none absolute left-4 right-4 rounded-lg bg-gradient-to-r from-sky-300 to-cyan-300 shadow-[0_6px_20px_rgba(56,189,248,0.25)] transition-all duration-300 ease-out'
    : 'pointer-events-none absolute left-4 right-4 rounded-lg bg-cyan-500 shadow-lg transition-all duration-300 ease-out';
  const settingsButtonClass = isLight
    ? 'inline-flex h-10 min-w-[56px] px-4 items-center justify-center rounded-xl border border-[#d9e6f2] bg-white text-slate-700 hover:border-sky-300 hover:text-sky-700 transition'
    : 'inline-flex h-10 min-w-[56px] px-4 items-center justify-center rounded-xl border border-slate-700 bg-slate-900/70 text-slate-200 hover:border-cyan-500/40 hover:text-cyan-200 transition';

  const updateActiveIndicator = useCallback(() => {
    const navEl = navRef.current;
    const activeEl = itemRefs.current[activeView];

    if (!navEl || !activeEl) {
      setActiveIndicator((prev) => ({ ...prev, ready: false }));
      return;
    }

    const navRect = navEl.getBoundingClientRect();
    const activeRect = activeEl.getBoundingClientRect();
    const top = activeRect.top - navRect.top + navEl.scrollTop;

    setActiveIndicator({
      top,
      height: activeRect.height,
      ready: true,
    });
  }, [activeView]);

  useLayoutEffect(() => {
    updateActiveIndicator();

    const navEl = navRef.current;
    const onResize = () => updateActiveIndicator();
    const onScroll = () => updateActiveIndicator();

    window.addEventListener('resize', onResize);
    navEl?.addEventListener('scroll', onScroll, { passive: true });

    return () => {
      window.removeEventListener('resize', onResize);
      navEl?.removeEventListener('scroll', onScroll);
    };
  }, [updateActiveIndicator, menuItems.length]);

  return (
    <div className={sidebarShellClass}>
      {/* Logo */}
      <div className={`p-6 ${logoBorderClass}`}>
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-lg flex items-center justify-center">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className={titleClass}>SECA</h1>
            <p className={subtitleClass}>{translateText('Security Analyzer')}</p>
          </div>
        </div>
      </div>

      {/* User Info */}
      <div className={`p-4 ${userBorderClass}`}>
        <div className={`flex items-center gap-3 px-3 py-3 rounded-xl ${userCardClass} ${userCardToneClass}`}>
          <div className={`w-9 h-9 rounded-full flex items-center justify-center ${userIconToneClass}`}>
            <User className="w-4 h-4" />
          </div>
          <div className="flex-1 min-w-0">
            <p className={userNameClass}>{userDisplayName}</p>
            <p className={emailClass}>{user?.email}</p>
            <p className={userRoleClass}>
              {user?.is_admin ? (
                <span className={`${userMetaAccentClass} font-medium`}>{translateText('Admin')}</span>
              ) : (
                <span className={userMetaAccentClass}>{user?.department || translateText('User')}</span>
              )}
            </p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav ref={navRef} className="relative flex-1 p-4 space-y-1 overflow-y-auto">
        <div
          className={`${navIndicatorClass} ${
            activeIndicator.ready ? 'opacity-100' : 'opacity-0'
          }`}
          style={{
            top: activeIndicator.top,
            height: activeIndicator.height,
          }}
        />
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeView === item.id;

          return (
            <button
              key={item.id}
              ref={(el) => {
                itemRefs.current[item.id] = el;
              }}
              onClick={() => onViewChange(item.id)}
              className={`relative z-10 w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
                isActive
                  ? navActiveClass
                  : navDefaultClass
              }`}
            >
              <Icon className="w-5 h-5" />
              <span className="font-medium">{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="p-4 pt-2">
        <div className="relative" data-no-i18n="true">
          <button
            type="button"
            onClick={() => onViewChange('settings')}
            className={`${settingsButtonClass} ${activeView === 'settings' ? (isLight ? 'border-sky-400 text-sky-700' : 'border-cyan-400 text-cyan-200') : ''}`}
            aria-label={translateText('Parameters')}
            title={translateText('Parameters')}
          >
            <Settings className="h-5 w-5" />
          </button>
        </div>
      </div>
    </div>
  );
}
