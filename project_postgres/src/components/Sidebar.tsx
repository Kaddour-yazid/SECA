import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { FileText, Globe, Hash, LayoutDashboard, Network, Settings, ShieldBan, ScrollText } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useLanguage } from '../contexts/LanguageContext';
import { useTheme } from '../contexts/ThemeContext';

type SidebarProps = {
  activeView: string;
  onViewChange: (view: string) => void;
};

type MenuItem = {
  id: string;
  label: string;
  icon: typeof LayoutDashboard;
};

type MenuGroup = {
  id: string;
  label: string;
  items: MenuItem[];
};

export function Sidebar({ activeView, onViewChange }: SidebarProps) {
  const { user } = useAuth();
  const { translateText } = useLanguage();
  const { theme } = useTheme();
  const navRef = useRef<HTMLElement | null>(null);
  const itemRefs = useRef<Record<string, HTMLButtonElement | null>>({});
  const hoverTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [isHovered, setIsHovered] = useState(false);
  const [activeIndicator, setActiveIndicator] = useState({
    top: 0,
    height: 0,
    ready: false,
  });

  const isCollapsed = !isHovered;

  const scanningItems: MenuItem[] = [
    { id: 'dashboard', label: translateText('Dashboard'), icon: LayoutDashboard },
    { id: 'file', label: translateText('File Scanner'), icon: FileText },
    { id: 'url', label: translateText('URL Scanner'), icon: Globe },
    { id: 'hash', label: translateText('Hash Checker'), icon: Hash },
  ];

  const monitoringItems: MenuItem[] = user?.is_admin
    ? [
        { id: 'start', label: translateText('Monitoring'), icon: Network },
        { id: 'audit', label: translateText('Audit Logs'), icon: ScrollText },
        { id: 'access-control', label: translateText('Access Control'), icon: ShieldBan },
      ]
    : [];

  const groups: MenuGroup[] = [
    { id: 'scan', label: 'Scanning', items: scanningItems },
    ...(monitoringItems.length > 0 ? [{ id: 'monitor', label: 'Monitoring', items: monitoringItems }] : []),
  ];

  const menuItems = groups.flatMap((group) => group.items);

  const isLight = theme === 'light';
  const sidebarShellClass = isLight
    ? `${isCollapsed ? 'w-20' : 'w-64'} overflow-hidden bg-[#f8fbff] border-r border-[#d9e6f2] flex flex-col transition-[width] duration-500 ease-[cubic-bezier(0.22,1,0.36,1)]`
    : `${isCollapsed ? 'w-20' : 'w-64'} overflow-hidden bg-slate-800 border-r border-slate-700 flex flex-col transition-[width] duration-500 ease-[cubic-bezier(0.22,1,0.36,1)]`;
  const navDefaultClass = isLight
    ? 'text-slate-700 bg-transparent hover:bg-sky-100 hover:text-sky-700'
    : 'text-slate-300 bg-transparent hover:bg-cyan-500/10 hover:text-cyan-400';
  const navActiveClass = isLight ? 'text-sky-900' : 'text-white';
  const navIndicatorClass = isLight
    ? `pointer-events-none absolute ${isCollapsed ? 'left-2 right-2' : 'left-4 right-4'} rounded-lg bg-gradient-to-r from-sky-300 to-cyan-300 shadow-[0_6px_20px_rgba(56,189,248,0.25)] transition-all duration-500 ease-[cubic-bezier(0.22,1,0.36,1)]`
    : `pointer-events-none absolute ${isCollapsed ? 'left-2 right-2' : 'left-4 right-4'} rounded-lg bg-cyan-500 shadow-lg transition-all duration-500 ease-[cubic-bezier(0.22,1,0.36,1)]`;
  const settingsButtonClass = isLight
    ? `inline-flex h-10 ${isCollapsed ? 'w-10' : 'min-w-[200px] px-4'} items-center justify-center rounded-xl border border-[#d9e6f2] bg-white text-slate-700 hover:border-sky-300 hover:text-sky-700 transition-all duration-300`
    : `inline-flex h-10 ${isCollapsed ? 'w-10' : 'min-w-[200px] px-4'} items-center justify-center rounded-xl border border-slate-700 bg-slate-900/70 text-slate-200 hover:border-cyan-500/40 hover:text-cyan-200 transition-all duration-300`;
  const dividerClass = isLight ? 'bg-slate-300/80' : 'bg-white/10';
  const sectionLabelClass = isLight ? 'text-slate-500' : 'text-slate-500';

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
  }, [updateActiveIndicator, menuItems.length, isCollapsed]);

  useEffect(() => {
    return () => {
      if (hoverTimeoutRef.current) {
        clearTimeout(hoverTimeoutRef.current);
      }
    };
  }, []);

  const handleMouseEnter = () => {
    if (hoverTimeoutRef.current) {
      clearTimeout(hoverTimeoutRef.current);
      hoverTimeoutRef.current = null;
    }
    setIsHovered(true);
  };

  const handleMouseLeave = () => {
    if (hoverTimeoutRef.current) {
      clearTimeout(hoverTimeoutRef.current);
    }
    hoverTimeoutRef.current = setTimeout(() => {
      setIsHovered(false);
      hoverTimeoutRef.current = null;
    }, 120);
  };

  return (
    <div
      className={sidebarShellClass}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
    >
      <nav
        ref={navRef}
        className={`relative flex-1 ${isCollapsed ? 'px-2 py-4' : 'px-4 py-5'} overflow-y-auto [&::-webkit-scrollbar]:hidden`}
        style={{ scrollbarWidth: 'none', msOverflowStyle: 'none' }}
      >
        <div
          className={`${navIndicatorClass} ${activeIndicator.ready ? 'opacity-100' : 'opacity-0'}`}
          style={{
            top: activeIndicator.top,
            height: activeIndicator.height,
          }}
        />

        <div className="space-y-5">
          {groups.map((group) => (
            <section key={group.id} className="space-y-2">
              <div className={`flex items-center ${isCollapsed ? 'justify-center px-2' : 'gap-3 px-2'}`}>
                <div className={`h-px ${isCollapsed ? 'w-8' : 'flex-1'} ${dividerClass}`} />
                {!isCollapsed && (
                  <span className={`shrink-0 text-[10px] font-semibold uppercase tracking-[0.18em] ${sectionLabelClass}`}>
                    {group.label}
                  </span>
                )}
                {!isCollapsed && <div className={`h-px flex-1 ${dividerClass}`} />}
              </div>

              <div className="space-y-1">
                {group.items.map((item) => {
                  const Icon = item.icon;
                  const isActive = activeView === item.id;

                  return (
                    <button
                      key={item.id}
                      ref={(el) => {
                        itemRefs.current[item.id] = el;
                      }}
                      onClick={() => onViewChange(item.id)}
                      className={`relative z-10 w-full flex items-center ${isCollapsed ? 'justify-center px-3' : 'gap-3 px-4'} py-3 rounded-lg transition-all duration-300 ${
                        isActive ? navActiveClass : navDefaultClass
                      }`}
                      aria-label={item.label}
                      title={isCollapsed ? item.label : undefined}
                    >
                      <Icon className="h-5 w-5 shrink-0" />
                      <span
                        className={`overflow-hidden whitespace-nowrap font-medium transition-all duration-300 ease-out ${
                          isCollapsed ? 'max-w-0 translate-x-1 opacity-0' : 'max-w-[160px] translate-x-0 opacity-100'
                        }`}
                      >
                        {item.label}
                      </span>
                    </button>
                  );
                })}
              </div>
            </section>
          ))}
        </div>
      </nav>

      <div className={`${isCollapsed ? 'px-2 pb-4 pt-2' : 'px-4 pb-4 pt-2'} transition-all duration-300`}>
        <div className={`flex items-center ${isCollapsed ? 'justify-center px-2' : 'gap-3 px-2'} mb-2`}>
          <div className={`h-px ${isCollapsed ? 'w-8' : 'flex-1'} ${dividerClass}`} />
          {!isCollapsed && (
            <span className={`shrink-0 text-[10px] font-semibold uppercase tracking-[0.18em] ${sectionLabelClass}`}>
              System
            </span>
          )}
          {!isCollapsed && <div className={`h-px flex-1 ${dividerClass}`} />}
        </div>
        <div className={`relative ${isCollapsed ? 'flex justify-center' : ''}`} data-no-i18n="true">
          <button
            type="button"
            onClick={() => onViewChange('settings')}
            className={`${settingsButtonClass} ${activeView === 'settings' ? (isLight ? 'border-sky-400 text-sky-700' : 'border-cyan-400 text-cyan-200') : ''} ${isCollapsed ? '' : 'gap-2.5'}`}
            aria-label={translateText('Parameters')}
            title={translateText('Parameters')}
          >
            <Settings className="h-5 w-5" />
            {!isCollapsed && (
              <span className="text-sm font-medium">
                {translateText('Parameters')}
              </span>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
