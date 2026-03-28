import { createContext, useContext, useState, useEffect } from 'react';
import { apiUrl } from '../config/api';

type User = {
  id: number;
  email: string;
  is_admin: boolean;
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
  signIn: (email: string, password: string) => Promise<boolean>;
  requestSignUpOtp: (payload: SignupPayload) => Promise<OtpResponse>;
  verifySignUpOtp: (email: string, code: string) => Promise<boolean>;
  requestPasswordResetOtp: (email: string) => Promise<OtpResponse>;
  confirmPasswordReset: (email: string, code: string, newPassword: string) => Promise<boolean>;
  signOut: () => void;
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

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

  useEffect(() => {
    if (token) {
      fetch(apiUrl('/me'), {
        headers: { Authorization: `Bearer ${token}` }
      })
        .then(res => {
          if (!res.ok) throw new Error('Invalid token');
          return res.json();
        })
        .then(data => setUser(data))
        .catch(() => {
          localStorage.removeItem('token');
          setToken(null);
          setUser(null);
        });
    }
  }, [token]);

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
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
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
