import { createContext, useContext, useState, useEffect } from 'react';
import { apiUrl } from '../config/api';

type User = {
  id: number;
  email: string;
  is_admin: boolean;
  admin_department?: boolean;
  role?: string | null;
  first_name?: string | null;
  last_name?: string | null;
  sex?: string | null;
  department?: string | null;
  group_name?: string | null;
};

type SignupPayload = {
  first_name: string;
  last_name: string;
  email: string;
  sex: string;
  department: string;
  group_name: string;
  password: string;
};

type OtpResponse = {
  email: string;
  message: string;
  expires_in_minutes?: number;
  resend_cooldown_seconds?: number;
  delivery?: string;
  debug_code?: string;
};

type AuthContextType = {
  user: User | null;
  token: string | null;
  authReady: boolean;
  signIn: (email: string, password: string) => Promise<boolean>;
  requestSignUpOtp: (payload: SignupPayload) => Promise<OtpResponse>;
  verifySignUpOtp: (email: string, code: string) => Promise<boolean>;
  requestPasswordResetOtp: (email: string) => Promise<OtpResponse>;
  confirmPasswordReset: (email: string, code: string, newPassword: string) => Promise<boolean>;
  signOut: () => void;
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const BROWSER_DEVICE_STORAGE_KEY = 'seca_browser_device_id';
const BROWSER_SESSION_STORAGE_KEY = 'seca_browser_session_id';

function randomId(prefix: string): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return `${prefix}-${crypto.randomUUID()}`;
  }
  return `${prefix}-${Math.random().toString(36).slice(2)}-${Date.now().toString(36)}`;
}

function getBrowserDeviceId(): string {
  const existing = localStorage.getItem(BROWSER_DEVICE_STORAGE_KEY);
  if (existing) return existing;
  const created = randomId('web');
  localStorage.setItem(BROWSER_DEVICE_STORAGE_KEY, created);
  return created;
}

function getBrowserSessionId(): string {
  const existing = localStorage.getItem(BROWSER_SESSION_STORAGE_KEY);
  if (existing) return existing;
  const created = randomId('session');
  localStorage.setItem(BROWSER_SESSION_STORAGE_KEY, created);
  return created;
}

function setBrowserSessionId(value: string): void {
  localStorage.setItem(BROWSER_SESSION_STORAGE_KEY, value);
}

function buildBrowserHeartbeatPayload() {
  const platformParts = [navigator.platform, navigator.userAgent].filter(Boolean);
  return {
    session_id: getBrowserSessionId(),
    device_id: getBrowserDeviceId(),
    hostname: '',
    app_version: 'web-client',
    platform: platformParts.join(' | ').slice(0, 240),
    local_ips: [],
  };
}

async function parseJson(res: Response) {
  const data = await res.json();
  if (!res.ok) {
    const errorMessage = typeof data.detail === 'string'
      ? data.detail
      : JSON.stringify(data.detail);
    throw new Error(errorMessage);
  }
  return data;
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  const [authReady, setAuthReady] = useState<boolean>(() => !localStorage.getItem('token'));

  useEffect(() => {
    if (!token) {
      setUser(null);
      setAuthReady(true);
      return;
    }

    const controller = new AbortController();
    setAuthReady(false);

    fetch(apiUrl('/me'), {
      headers: { Authorization: `Bearer ${token}` },
      signal: controller.signal,
    })
      .then(async (res) => {
        if (res.status === 401 || res.status === 403) {
          throw new Error('AUTH_INVALID');
        }
        if (!res.ok) {
          throw new Error(`AUTH_FETCH_FAILED:${res.status}`);
        }
        return res.json();
      })
      .then((data) => {
        setUser(data);
      })
      .catch((error: Error) => {
        if (controller.signal.aborted) {
          return;
        }
        if (error.message === 'AUTH_INVALID') {
          localStorage.removeItem('token');
          setToken(null);
          setUser(null);
          return;
        }
        // Keep the existing token on transient backend/network errors.
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setAuthReady(true);
        }
      });

    return () => controller.abort();
  }, [token]);

  useEffect(() => {
    if (!token || !user) {
      return;
    }

    let cancelled = false;
    let intervalId: number | null = null;

    const sendHeartbeat = async () => {
      try {
        const res = await fetch(apiUrl('/desktop/session/heartbeat'), {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify(buildBrowserHeartbeatPayload()),
        });

        if (!res.ok) {
          return;
        }

        const data = await res.json();
        const returnedSessionId = data?.session?.session_id;
        if (returnedSessionId) {
          setBrowserSessionId(String(returnedSessionId));
        }
      } catch {
        // Best-effort browser heartbeat; monitoring will expire stale sessions automatically.
      }
    };

    const stopHeartbeat = (reason: string) => {
      const payload = {
        session_id: getBrowserSessionId(),
        device_id: getBrowserDeviceId(),
        reason,
      };

      fetch(apiUrl('/desktop/session/stop'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(payload),
        keepalive: true,
      }).catch(() => undefined);
    };

    const handlePageHide = () => stopHeartbeat('browser-page-closed');
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        void sendHeartbeat();
      }
    };

    const startHeartbeatLoop = async () => {
      let intervalSeconds = 8;
      try {
        const configRes = await fetch(apiUrl('/desktop/session/config'), {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (configRes.ok) {
          const configData = await configRes.json();
          const configured = Number(configData?.heartbeat_interval_seconds);
          if (Number.isFinite(configured) && configured > 0) {
            intervalSeconds = configured;
          }
        }
      } catch {
        // Keep fallback interval.
      }

      if (cancelled) {
        return;
      }

      await sendHeartbeat();
      intervalId = window.setInterval(() => {
        void sendHeartbeat();
      }, intervalSeconds * 1000);
    };

    window.addEventListener('pagehide', handlePageHide);
    document.addEventListener('visibilitychange', handleVisibilityChange);
    void startHeartbeatLoop();

    return () => {
      cancelled = true;
      if (intervalId !== null) {
        window.clearInterval(intervalId);
      }
      window.removeEventListener('pagehide', handlePageHide);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      stopHeartbeat('browser-session-ended');
    };
  }, [token, user]);

  const signIn = async (email: string, password: string): Promise<boolean> => {
    const res = await fetch(apiUrl('/login'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    const data = await parseJson(res);
    localStorage.setItem('token', data.access_token);
    setToken(data.access_token);
    setUser(data.user);
    setAuthReady(true);
    return true;
  };

  const requestSignUpOtp = async (payload: SignupPayload): Promise<OtpResponse> => {
    const res = await fetch(apiUrl('/register/request-otp'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return parseJson(res);
  };

  const verifySignUpOtp = async (email: string, code: string): Promise<boolean> => {
    const res = await fetch(apiUrl('/register/verify-otp'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, code })
    });
    await parseJson(res);
    return true;
  };

  const requestPasswordResetOtp = async (email: string): Promise<OtpResponse> => {
    const res = await fetch(apiUrl('/password-reset/request-otp'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    return parseJson(res);
  };

  const confirmPasswordReset = async (email: string, code: string, newPassword: string): Promise<boolean> => {
    const res = await fetch(apiUrl('/password-reset/confirm'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, code, new_password: newPassword })
    });
    await parseJson(res);
    return true;
  };

  const signOut = () => {
    const tokenForStop = token;
    if (tokenForStop) {
      fetch(apiUrl('/desktop/session/stop'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokenForStop}`,
        },
        body: JSON.stringify({
          session_id: getBrowserSessionId(),
          device_id: getBrowserDeviceId(),
          reason: 'manual-logout',
        }),
        keepalive: true,
      }).catch(() => undefined);
    }
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
    setAuthReady(true);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        authReady,
        signIn,
        requestSignUpOtp,
        verifySignUpOtp,
        requestPasswordResetOtp,
        confirmPasswordReset,
        signOut,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
};
