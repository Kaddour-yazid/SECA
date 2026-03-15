import { useMemo, useState } from 'react';
import { Activity, ArrowLeft, Globe, KeyRound, Loader2, Lock, Mail, Shield } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

type AuthStep = 'login' | 'signup-request' | 'signup-verify' | 'reset-request' | 'reset-confirm';

export function LoginView() {
  const {
    signIn,
    requestSignUpOtp,
    verifySignUpOtp,
    requestPasswordResetOtp,
    confirmPasswordReset,
  } = useAuth();

  const [step, setStep] = useState<AuthStep>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [otpMeta, setOtpMeta] = useState<{ expires?: number; cooldown?: number; debugCode?: string; delivery?: string } | null>(null);

  const heading = useMemo(() => {
    switch (step) {
      case 'signup-request':
        return { title: 'Create Account', subtitle: 'Verify ownership of your email before the account is created.' };
      case 'signup-verify':
        return { title: 'Verify Email', subtitle: 'Enter the one-time code sent to your inbox.' };
      case 'reset-request':
        return { title: 'Recover Password', subtitle: 'Request a reset code for your existing user account.' };
      case 'reset-confirm':
        return { title: 'Set New Password', subtitle: 'Use the reset code to assign a new password.' };
      default:
        return { title: 'Sign In', subtitle: 'Access your SECA workspace with your verified account.' };
    }
  }, [step]);

  const resetMessages = () => {
    setError(null);
    setSuccess(null);
  };

  const switchStep = (next: AuthStep) => {
    setStep(next);
    setOtpCode('');
    if (next !== 'signup-verify' && next !== 'reset-confirm') {
      setOtpMeta(null);
    }
    if (next !== 'reset-confirm') {
      setNewPassword('');
    }
    resetMessages();
  };

  const handleLogin = async () => {
    const ok = await signIn(email, password);
    if (ok) {
      setSuccess('Login successful. Redirecting...');
    }
  };

  const handleSignupRequest = async () => {
    const response = await requestSignUpOtp(email, password);
    setOtpMeta({
      expires: response.expires_in_minutes,
      cooldown: response.resend_cooldown_seconds,
      debugCode: response.debug_code,
      delivery: response.delivery,
    });
    setSuccess(response.message);
    setStep('signup-verify');
  };

  const handleSignupVerify = async () => {
    const ok = await verifySignUpOtp(email, otpCode);
    if (ok) {
      setSuccess('Email verified. You can now sign in with your password.');
      setPassword('');
      setOtpCode('');
      setOtpMeta(null);
      setStep('login');
    }
  };

  const handleResetRequest = async () => {
    const response = await requestPasswordResetOtp(email);
    setOtpMeta({
      expires: response.expires_in_minutes,
      cooldown: response.resend_cooldown_seconds,
      debugCode: response.debug_code,
      delivery: response.delivery,
    });
    setSuccess(response.message);
    setStep('reset-confirm');
  };

  const handleResetConfirm = async () => {
    const ok = await confirmPasswordReset(email, otpCode, newPassword);
    if (ok) {
      setSuccess('Password updated. Sign in with the new password.');
      setPassword('');
      setNewPassword('');
      setOtpCode('');
      setOtpMeta(null);
      setStep('login');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    resetMessages();

    try {
      if (step === 'login') {
        await handleLogin();
      } else if (step === 'signup-request') {
        await handleSignupRequest();
      } else if (step === 'signup-verify') {
        await handleSignupVerify();
      } else if (step === 'reset-request') {
        await handleResetRequest();
      } else if (step === 'reset-confirm') {
        await handleResetConfirm();
      }
    } catch (err) {
      console.error('Auth error:', err);
      setError(err instanceof Error ? err.message : 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  const showPassword = step === 'login' || step === 'signup-request';
  const showOtp = step === 'signup-verify' || step === 'reset-confirm';
  const showNewPassword = step === 'reset-confirm';

  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(34,211,238,0.18),_transparent_35%),linear-gradient(135deg,#08111f_0%,#0f172a_48%,#111827_100%)] flex items-center justify-center p-4">
      <div className="w-full max-w-5xl grid lg:grid-cols-[1.15fr_0.85fr] gap-6">
        <section className="hidden lg:flex rounded-3xl border border-cyan-900/40 bg-slate-950/55 backdrop-blur-xl p-10 flex-col justify-between shadow-[0_30px_80px_rgba(8,15,30,0.45)]">
          <div>
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan-400 to-blue-600 shadow-lg shadow-cyan-500/20 mb-6">
              <Shield className="w-8 h-8 text-white" />
            </div>
            <p className="text-cyan-300 text-sm uppercase tracking-[0.32em] mb-4">SECA Platform</p>
            <h1 className="text-4xl font-bold text-white leading-tight mb-4">
              Security analysis, monitoring, and access control from one workspace.
            </h1>
          </div>

          <div className="grid gap-4">
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
              <div className="flex items-center gap-3 mb-2 text-white font-semibold">
                <Activity className="w-5 h-5 text-emerald-400" />
                Multi-layer threat analysis
              </div>
              <p className="text-sm text-slate-400">Analyze files, URLs, hashes, and emails with unified verdicts and detailed reports.</p>
            </div>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
              <div className="flex items-center gap-3 mb-2 text-white font-semibold">
                <Globe className="w-5 h-5 text-amber-400" />
                Monitoring and enforcement
              </div>
              <p className="text-sm text-slate-400">Track gateway activity, review audit logs, and manage policy decisions from the same dashboard.</p>
            </div>
          </div>
        </section>

        <section className="rounded-3xl border border-slate-800 bg-slate-900/82 backdrop-blur-xl p-8 shadow-[0_24px_70px_rgba(8,15,30,0.45)]">
          <div className="flex items-center justify-between mb-8">
            <div>
              <p className="text-cyan-300 text-xs uppercase tracking-[0.3em] mb-3">Account Security</p>
              <h2 className="text-3xl font-bold text-white mb-2">{heading.title}</h2>
              <p className="text-slate-400 max-w-md">{heading.subtitle}</p>
            </div>
            {step !== 'login' && (
              <button
                type="button"
                onClick={() => switchStep('login')}
                className="inline-flex items-center gap-2 rounded-xl border border-slate-700 px-4 py-2 text-slate-300 hover:text-white hover:border-slate-500 transition"
              >
                <ArrowLeft className="w-4 h-4" />
                Back
              </button>
            )}
          </div>

          <div className="flex gap-2 mb-6">
            <button
              type="button"
              onClick={() => switchStep('login')}
              className={`flex-1 py-3 rounded-xl font-medium transition ${
                step === 'login'
                  ? 'bg-cyan-500 text-white shadow-lg shadow-cyan-500/20'
                  : 'bg-slate-950/40 text-slate-400 hover:text-white'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => switchStep('signup-request')}
              className={`flex-1 py-3 rounded-xl font-medium transition ${
                step === 'signup-request' || step === 'signup-verify'
                  ? 'bg-cyan-500 text-white shadow-lg shadow-cyan-500/20'
                  : 'bg-slate-950/40 text-slate-400 hover:text-white'
              }`}
            >
              Sign Up
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Email</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-10 pr-4 py-3 bg-slate-950/60 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent transition"
                  placeholder="your@email.com"
                  required
                  disabled={loading || step === 'signup-verify' || step === 'reset-confirm'}
                />
              </div>
            </div>

            {showPassword && (
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  {step === 'signup-request' ? 'Create Password' : 'Password'}
                </label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full pl-10 pr-4 py-3 bg-slate-950/60 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent transition"
                    placeholder="Minimum 8 characters"
                    required
                    minLength={8}
                    disabled={loading}
                  />
                </div>
              </div>
            )}

            {showOtp && (
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">One-Time Code</label>
                <div className="relative">
                  <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
                  <input
                    type="text"
                    value={otpCode}
                    onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    className="w-full pl-10 pr-4 py-3 bg-slate-950/60 border border-slate-700 rounded-xl text-white tracking-[0.35em] placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent transition"
                    placeholder="000000"
                    required
                    disabled={loading}
                  />
                </div>
                {otpMeta?.expires && (
                  <p className="mt-2 text-sm text-slate-400">
                    Code expires in {otpMeta.expires} minutes{otpMeta.cooldown ? ` and can be re-sent after ${otpMeta.cooldown}s.` : '.'}
                  </p>
                )}
              </div>
            )}

            {showNewPassword && (
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">New Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
                  <input
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="w-full pl-10 pr-4 py-3 bg-slate-950/60 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent transition"
                    placeholder="Minimum 8 characters"
                    required
                    minLength={8}
                    disabled={loading}
                  />
                </div>
              </div>
            )}

            {error && (
              <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">
                {error}
              </div>
            )}

            {success && (
              <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-300">
                <p>{success}</p>
                {otpMeta?.delivery === 'development_fallback' && otpMeta?.debugCode && (
                  <p className="mt-2 font-mono text-emerald-200">Dev OTP: {otpMeta.debugCode}</p>
                )}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold rounded-xl hover:from-cyan-600 hover:to-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Processing...
                </>
              ) : (
                <>
                  {step === 'login' && 'Sign In'}
                  {step === 'signup-request' && 'Send Verification Code'}
                  {step === 'signup-verify' && 'Verify and Create Account'}
                  {step === 'reset-request' && 'Send Reset Code'}
                  {step === 'reset-confirm' && 'Update Password'}
                </>
              )}
            </button>
          </form>

          <div className="mt-6 flex items-center justify-between text-sm">
            <button
              type="button"
              onClick={() => switchStep(step === 'reset-request' || step === 'reset-confirm' ? 'login' : 'reset-request')}
              className="text-slate-400 hover:text-cyan-300 transition"
            >
              {step === 'reset-request' || step === 'reset-confirm' ? 'Back to sign in' : 'Forgot password?'}
            </button>
            <p className="text-slate-500">Admin accounts are provisioned only by the local admin script.</p>
          </div>
        </section>
      </div>
    </div>
  );
}
