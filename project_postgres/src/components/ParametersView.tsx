import { Globe, LogOut, Monitor, Moon, Sun, UserRound } from 'lucide-react';
import { useMemo, useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { useLanguage, type Language } from '../contexts/LanguageContext';
import { useTheme } from '../contexts/ThemeContext';

type ParametersTab = 'language' | 'appearance' | 'account';

export function ParametersView() {
  const { user, signOut } = useAuth();
  const { language, setLanguage, translateText } = useLanguage();
  const { theme, setTheme } = useTheme();
  const [activeTab, setActiveTab] = useState<ParametersTab>('language');

  const languageOptions = useMemo(
    () => [
      { code: 'en' as Language, label: 'English' },
      { code: 'fr' as Language, label: 'Francais' },
      { code: 'ar' as Language, label: 'Arabic' },
    ],
    []
  );

  const tabButtonClass = (selected: boolean) =>
    `flex items-center gap-3 rounded-xl border px-4 py-3 text-left transition ${
      selected
        ? 'border-cyan-400 bg-cyan-500/10 text-white'
        : 'border-slate-700 bg-slate-900/60 text-slate-300 hover:border-slate-500 hover:text-white'
    }`;

  const optionButtonClass = (selected: boolean) =>
    `rounded-xl border px-4 py-3 text-left transition ${
      selected
        ? 'border-cyan-400 bg-cyan-500/10 text-white'
        : 'border-slate-700 bg-slate-950/40 text-slate-300 hover:border-slate-500 hover:text-white'
    }`;

  return (
    <div className="flex-1 bg-slate-900 global-scroll p-8 space-y-6">
      <div>
        <h2 className="text-3xl font-bold text-white">{translateText('Parameters')}</h2>
        <p className="text-slate-400 mt-2">{translateText('Manage your language, appearance, account, and session from one place.')}</p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[280px_minmax(0,1fr)] gap-6">
        <div className="bg-slate-800/50 border border-slate-700 rounded-2xl p-4 space-y-3">
          <button type="button" onClick={() => setActiveTab('language')} className={`w-full ${tabButtonClass(activeTab === 'language')}`}>
            <Globe className="w-5 h-5" />
            <div>
              <p className="font-medium">{translateText('Language Settings')}</p>
              <p className="text-xs text-slate-400">{translateText('Choose the interface language.')}</p>
            </div>
          </button>

          <button type="button" onClick={() => setActiveTab('appearance')} className={`w-full ${tabButtonClass(activeTab === 'appearance')}`}>
            <Monitor className="w-5 h-5" />
            <div>
              <p className="font-medium">{translateText('Appearance Settings')}</p>
              <p className="text-xs text-slate-400">{translateText('Switch between light and dark mode.')}</p>
            </div>
          </button>

          <button type="button" onClick={() => setActiveTab('account')} className={`w-full ${tabButtonClass(activeTab === 'account')}`}>
            <UserRound className="w-5 h-5" />
            <div>
              <p className="font-medium">{translateText('Account Settings')}</p>
              <p className="text-xs text-slate-400">{translateText('Review your current account information.')}</p>
            </div>
          </button>

          <button type="button" onClick={signOut} className="w-full flex items-center gap-3 rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-left text-rose-200 transition hover:border-rose-400 hover:bg-rose-500/15">
            <LogOut className="w-5 h-5" />
            <div>
              <p className="font-medium">{translateText('Logout')}</p>
              <p className="text-xs text-rose-200/70">{translateText('End the current session securely.')}</p>
            </div>
          </button>
        </div>

        <div className="bg-slate-800/50 border border-slate-700 rounded-2xl p-6">
          {activeTab === 'language' && (
            <div className="space-y-5">
              <div>
                <h3 className="text-xl font-semibold text-white">{translateText('Language Settings')}</h3>
                <p className="text-slate-400 mt-1">{translateText('Select the language used across the SECA interface.')}</p>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {languageOptions.map((option) => (
                  <button
                    key={option.code}
                    type="button"
                    onClick={() => setLanguage(option.code)}
                    className={optionButtonClass(language === option.code)}
                  >
                    <p className="font-medium">{translateText(option.label)}</p>
                    <p className="text-xs uppercase tracking-[0.18em] text-slate-400 mt-1">{option.code}</p>
                  </button>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'appearance' && (
            <div className="space-y-5">
              <div>
                <h3 className="text-xl font-semibold text-white">{translateText('Appearance Settings')}</h3>
                <p className="text-slate-400 mt-1">{translateText('Choose how the platform should look on this device.')}</p>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <button type="button" onClick={() => setTheme('light')} className={optionButtonClass(theme === 'light')}>
                  <div className="flex items-center gap-3">
                    <Sun className="w-5 h-5" />
                    <div>
                      <p className="font-medium">{translateText('Light Mode')}</p>
                      <p className="text-xs text-slate-400">{translateText('Use a brighter interface.')}</p>
                    </div>
                  </div>
                </button>
                <button type="button" onClick={() => setTheme('dark')} className={optionButtonClass(theme === 'dark')}>
                  <div className="flex items-center gap-3">
                    <Moon className="w-5 h-5" />
                    <div>
                      <p className="font-medium">{translateText('Dark Mode')}</p>
                      <p className="text-xs text-slate-400">{translateText('Use a darker interface.')}</p>
                    </div>
                  </div>
                </button>
              </div>
            </div>
          )}

          {activeTab === 'account' && (
            <div className="space-y-5">
              <div>
                <h3 className="text-xl font-semibold text-white">{translateText('Account Settings')}</h3>
                <p className="text-slate-400 mt-1">{translateText('Current account information for the active session.')}</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                  <p className="text-sm text-slate-400">{translateText('Email')}</p>
                  <p className="text-white font-medium mt-1 break-all">{user?.email || '-'}</p>
                </div>
                <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                  <p className="text-sm text-slate-400">{translateText('Role')}</p>
                  <p className="text-white font-medium mt-1">{user?.is_admin ? translateText('Admin') : translateText('User')}</p>
                </div>
              </div>

              <div className="rounded-xl border border-dashed border-slate-700 bg-slate-900/40 p-4">
                <p className="text-slate-200 font-medium">{translateText('More account options will be added here.')}</p>
                <p className="text-slate-400 text-sm mt-1">{translateText('For now, this section shows the active account and lets you manage language, theme, and logout from this page.')}</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
