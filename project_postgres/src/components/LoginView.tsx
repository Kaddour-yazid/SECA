import { useEffect, useMemo, useState } from 'react';
import {
  ArrowLeft,
  BarChart3,
  Clock3,
  FileSearch,
  Fingerprint,
  Globe,
  History,
  KeyRound,
  LayoutDashboard,
  Link2,
  Loader2,
  Lock,
  Mail,
  Radar,
  ShieldCheck,
  Shield,
  Workflow,
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

type AuthStep = 'login' | 'signup-profile' | 'signup-organization' | 'signup-verify' | 'reset-request' | 'reset-confirm';

type FeatureSlide = {
  eyebrow: string;
  title: string;
  description: string;
  points: { label: string; icon: JSX.Element }[];
  icon: JSX.Element;
  accent: string;
};

const featureSlides: FeatureSlide[] = [
  {
    eyebrow: 'File Scanner',
    title: 'Analyze suspicious files with layered inspection',
    description:
      'SECA helps analysts review files through static inspection, verdict scoring, and controlled escalation paths for deeper investigation.',
    points: [
      { label: 'Static verdicts and evidence', icon: <ShieldCheck className="h-4 w-4" /> },
      { label: 'Hash-based lookups', icon: <Fingerprint className="h-4 w-4" /> },
      { label: 'Escalation toward deeper inspection', icon: <Radar className="h-4 w-4" /> },
    ],
    icon: <FileSearch className="h-8 w-8 text-cyan-300" />,
    accent: 'from-cyan-500/20 to-blue-500/5',
  },
  {
    eyebrow: 'URL Intelligence',
    title: 'Review risky links before users interact with them',
    description:
      'The platform evaluates URLs using heuristics, known indicators, and contextual analysis so suspicious destinations can be assessed quickly.',
    points: [
      { label: 'Heuristic URL review', icon: <Globe className="h-4 w-4" /> },
      { label: 'Threat-feed correlation', icon: <Link2 className="h-4 w-4" /> },
      { label: 'Safer decision support for analysts', icon: <Shield className="h-4 w-4" /> },
    ],
    icon: <Globe className="h-8 w-8 text-sky-300" />,
    accent: 'from-sky-500/20 to-indigo-500/5',
  },
  {
    eyebrow: 'Dashboard',
    title: 'Monitor activity and security posture from one surface',
    description:
      'Dashboard views consolidate scan outcomes, operational signals, and usage patterns to make SECA easier to use as a daily analysis workspace.',
    points: [
      { label: 'Centralized operational visibility', icon: <LayoutDashboard className="h-4 w-4" /> },
      { label: 'Readable indicators and counts', icon: <BarChart3 className="h-4 w-4" /> },
      { label: 'Faster navigation between modules', icon: <Workflow className="h-4 w-4" /> },
    ],
    icon: <LayoutDashboard className="h-8 w-8 text-indigo-300" />,
    accent: 'from-indigo-500/20 to-cyan-500/5',
  },
  {
    eyebrow: 'Audit History',
    title: 'Keep a traceable history of what happened and when',
    description:
      'SECA preserves investigation history and audit events so the team can move from one isolated scan to a broader operational narrative.',
    points: [
      { label: 'Audit-ready event visibility', icon: <History className="h-4 w-4" /> },
      { label: 'Investigation continuity', icon: <Clock3 className="h-4 w-4" /> },
      { label: 'Better accountability for actions', icon: <ShieldCheck className="h-4 w-4" /> },
    ],
    icon: <History className="h-8 w-8 text-emerald-300" />,
    accent: 'from-emerald-500/20 to-cyan-500/5',
  },
];

const departmentGroups = {
  RXS: [
    'Infrastructure (Sauvegarde & Stockage)',
    'Service Système (Messagerie, Identité & Accès)',
    'Service Interconnexion (Routage, Commutation & Sécurité Périmétrique)',
    'Service Support (Matériel & Déploiement Logiciel)',
    'Service Data Center',
  ],
  SLM: [
    'Groupe GED',
    'Groupe Maintenance',
    'Groupe DBA',
    'Groupe Développement',
    'Groupe Qualité',
    'Groupe Décisionnel & Veille Technologique',
  ],
  SSI: [
    'Pôle SOC & Sécurité des systèmes',
    'Pôle Sécurité Industrielle (OT)',
    'Pôle Sécurité Applicative & Gouvernance',
  ],
} as const;

const sexOptions = [
  { value: 'male', label: 'Male' },
  { value: 'female', label: 'Female' },
];

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
  const [confirmPassword, setConfirmPassword] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [signupFirstName, setSignupFirstName] = useState('');
  const [signupLastName, setSignupLastName] = useState('');
  const [signupSex, setSignupSex] = useState<'male' | 'female'>('male');
  const [signupDepartment, setSignupDepartment] = useState<keyof typeof departmentGroups | ''>('');
  const [signupGroup, setSignupGroup] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [activeSlide, setActiveSlide] = useState(0);
  const [signupOtpRequested, setSignupOtpRequested] = useState(false);
  const [otpMeta, setOtpMeta] = useState<{ expires?: number; cooldown?: number; debugCode?: string; delivery?: string } | null>(null);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setActiveSlide((current) => (current + 1) % featureSlides.length);
    }, 5000);
    return () => window.clearInterval(timer);
  }, []);

  const heading = useMemo(() => {
    switch (step) {
      case 'signup-profile':
        return { title: 'Create Account', subtitle: 'Start with your identity details before we prepare your SECA access.' };
      case 'signup-organization':
        return { title: 'Your Organization', subtitle: 'Select your department and group so your account matches the right internal context.' };
      case 'signup-verify':
        return { title: 'Secure and Verify', subtitle: 'Create your password and confirm the OTP sent to your email to finalize registration.' };
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

  const resetSignupFlow = () => {
    setSignupFirstName('');
    setSignupLastName('');
    setSignupSex('male');
    setSignupDepartment('');
    setSignupGroup('');
    setPassword('');
    setConfirmPassword('');
    setOtpCode('');
    setSignupOtpRequested(false);
    setOtpMeta(null);
  };

  const switchStep = (next: AuthStep) => {
    const leavingSignup = ['signup-profile', 'signup-organization', 'signup-verify'].includes(step);
    const enteringSignup = ['signup-profile', 'signup-organization', 'signup-verify'].includes(next);
    setStep(next);
    if (next !== 'signup-verify') {
      setOtpCode('');
    }
    if (next !== 'signup-verify' && next !== 'reset-confirm') {
      setOtpMeta(null);
    }
    if (next !== 'reset-confirm') {
      setNewPassword('');
    }
    if (!enteringSignup && leavingSignup) {
      resetSignupFlow();
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
    if (password.length < 8) {
      throw new Error('Password must contain at least 8 characters');
    }
    if (password !== confirmPassword) {
      throw new Error('Password confirmation does not match');
    }
    if (!signupDepartment || !signupGroup) {
      throw new Error('Please select a department and group before requesting the OTP');
    }

    const response = await requestSignUpOtp({
      first_name: signupFirstName,
      last_name: signupLastName,
      email,
      sex: signupSex,
      department: signupDepartment,
      group_name: signupGroup,
      password,
    });
    setOtpMeta({
      expires: response.expires_in_minutes,
      cooldown: response.resend_cooldown_seconds,
      debugCode: response.debug_code,
      delivery: response.delivery,
    });
    setSuccess(response.message);
    setSignupOtpRequested(true);
  };

  const handleSignupVerify = async () => {
    const ok = await verifySignUpOtp(email, otpCode);
    if (ok) {
      setSuccess('Email verified. You can now sign in with your password.');
      resetSignupFlow();
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
      } else if (step === 'signup-profile') {
        if (!signupFirstName.trim() || !signupLastName.trim() || !email.trim()) {
          throw new Error('Please complete all required identity fields');
        }
        switchStep('signup-organization');
      } else if (step === 'signup-organization') {
        if (!signupDepartment || !signupGroup) {
          throw new Error('Please select your department and group');
        }
        switchStep('signup-verify');
      } else if (step === 'signup-verify') {
        if (!signupOtpRequested) {
          await handleSignupRequest();
        } else {
          await handleSignupVerify();
        }
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

  const handleBackNavigation = () => {
    if (step === 'signup-organization') {
      switchStep('signup-profile');
      return;
    }
    if (step === 'signup-verify') {
      switchStep('signup-organization');
      return;
    }
    if (step === 'reset-confirm') {
      switchStep('reset-request');
      return;
    }
    switchStep('login');
  };

  const showPassword = step === 'login';
  const showOtp = (step === 'signup-verify' && signupOtpRequested) || step === 'reset-confirm';
  const showNewPassword = step === 'reset-confirm';
  const isSignupFlow = step === 'signup-profile' || step === 'signup-organization' || step === 'signup-verify';
  const signupStepIndex =
    step === 'signup-profile' ? 0 : step === 'signup-organization' ? 1 : step === 'signup-verify' ? 2 : 0;
  const signupGroups = signupDepartment ? departmentGroups[signupDepartment] : [];

  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(34,211,238,0.18),_transparent_35%),linear-gradient(135deg,#08111f_0%,#0f172a_48%,#111827_100%)] flex items-center justify-center p-4">
      <div className="w-full max-w-[1480px]">
        <div className="grid items-stretch gap-6 lg:grid-cols-[minmax(390px,1.08fr)_minmax(0,2.25fr)]">
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
                onClick={handleBackNavigation}
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
              onClick={() => switchStep('signup-profile')}
              className={`flex-1 py-3 rounded-xl font-medium transition ${
                isSignupFlow
                  ? 'bg-cyan-500 text-white shadow-lg shadow-cyan-500/20'
                  : 'bg-slate-950/40 text-slate-400 hover:text-white'
              }`}
            >
              Sign Up
            </button>
          </div>

          {isSignupFlow && (
            <div className="mb-6 flex items-center gap-3">
              {[0, 1, 2].map((index) => (
                <div key={index} className="flex items-center gap-3">
                  <div
                    className={`flex h-8 w-8 items-center justify-center rounded-full border text-xs font-semibold transition ${
                      signupStepIndex >= index
                        ? 'border-cyan-400 bg-cyan-400/15 text-cyan-200'
                        : 'border-slate-700 text-slate-500'
                    }`}
                  >
                    {index + 1}
                  </div>
                  {index < 2 && (
                    <div className={`h-px w-8 ${signupStepIndex > index ? 'bg-cyan-400/60' : 'bg-slate-700'}`} />
                  )}
                </div>
              ))}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {step === 'login' && (
              <>
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
                      disabled={loading}
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">Password</label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
                    <input
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="w-full pl-10 pr-4 py-3 bg-slate-950/60 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent transition"
                      placeholder="Enter your password"
                      required
                      minLength={8}
                      disabled={loading}
                    />
                  </div>
                </div>
              </>
            )}

            {isSignupFlow && (
              <div className="overflow-hidden">
                <div
                  className="flex transition-transform duration-500 ease-out"
                  style={{ transform: `translateX(-${signupStepIndex * 100}%)` }}
                >
                  <div className="w-full shrink-0 space-y-4 pr-1">
                    <div className="grid gap-4 sm:grid-cols-2">
                      <div>
                        <label className="block text-sm font-medium text-slate-300 mb-2">First name</label>
                        <input
                          type="text"
                          value={signupFirstName}
                          onChange={(e) => setSignupFirstName(e.target.value)}
                          className="w-full px-4 py-3 bg-slate-950/60 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent transition"
                          placeholder="Your first name"
                          disabled={loading}
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-slate-300 mb-2">Last name</label>
                        <input
                          type="text"
                          value={signupLastName}
                          onChange={(e) => setSignupLastName(e.target.value)}
                          className="w-full px-4 py-3 bg-slate-950/60 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent transition"
                          placeholder="Your last name"
                          disabled={loading}
                        />
                      </div>
                    </div>
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
                          disabled={loading}
                        />
                      </div>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-300 mb-2">Sex</label>
                      <div className="grid grid-cols-2 gap-3">
                        {sexOptions.map((option) => (
                          <button
                            key={option.value}
                            type="button"
                            onClick={() => setSignupSex(option.value as 'male' | 'female')}
                            className={`rounded-xl border px-4 py-3 text-sm font-medium transition ${
                              signupSex === option.value
                                ? option.value === 'female'
                                  ? 'border-pink-400 bg-pink-500/15 text-pink-100'
                                  : 'border-cyan-400 bg-cyan-500/15 text-cyan-100'
                                : option.value === 'female'
                                  ? 'border-slate-700 bg-slate-950/40 text-slate-400 hover:border-purple-400/60 hover:bg-purple-500/10 hover:text-purple-100'
                                  : 'border-slate-700 bg-slate-950/40 text-slate-400 hover:text-white'
                            }`}
                          >
                            {option.label}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div className="w-full shrink-0 space-y-4 pr-1">
                    <div>
                      <label className="block text-sm font-medium text-slate-300 mb-2">Department</label>
                      <select
                        value={signupDepartment}
                        onChange={(e) => {
                          const value = e.target.value as keyof typeof departmentGroups | '';
                          setSignupDepartment(value);
                          setSignupGroup('');
                        }}
                        className="w-full px-4 py-3 bg-slate-950/60 border border-slate-700 rounded-xl text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent transition"
                        disabled={loading}
                      >
                        <option value="">Select department</option>
                        <option value="RXS">RXS</option>
                        <option value="SLM">SLM</option>
                        <option value="SSI">SSI</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-300 mb-2">Group</label>
                      <select
                        value={signupGroup}
                        onChange={(e) => setSignupGroup(e.target.value)}
                        className="w-full px-4 py-3 bg-slate-950/60 border border-slate-700 rounded-xl text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent transition"
                        disabled={loading || !signupDepartment}
                      >
                        <option value="">{signupDepartment ? 'Select group' : 'Select department first'}</option>
                        {signupGroups.map((groupName) => (
                          <option key={groupName} value={groupName}>
                            {groupName}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>

                  <div className="w-full shrink-0 space-y-4 pr-1">
                    <div className="grid gap-4 sm:grid-cols-2">
                      <div>
                        <label className="block text-sm font-medium text-slate-300 mb-2">Create password</label>
                        <div className="relative">
                          <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
                          <input
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            className="w-full pl-10 pr-4 py-3 bg-slate-950/60 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent transition"
                            placeholder="Minimum 8 characters"
                            minLength={8}
                            disabled={loading || signupOtpRequested}
                          />
                        </div>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-slate-300 mb-2">Confirm password</label>
                        <div className="relative">
                          <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
                          <input
                            type="password"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            className="w-full pl-10 pr-4 py-3 bg-slate-950/60 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent transition"
                            placeholder="Repeat your password"
                            minLength={8}
                            disabled={loading || signupOtpRequested}
                          />
                        </div>
                      </div>
                    </div>

                    {signupOtpRequested && (
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
                  </div>
                </div>
              </div>
            )}

            {step === 'reset-request' && (
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
                    disabled={loading}
                  />
                </div>
              </div>
            )}

            {showOtp && !isSignupFlow && (
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
                  {step === 'signup-profile' && 'Continue'}
                  {step === 'signup-organization' && 'Continue'}
                  {step === 'signup-verify' && (signupOtpRequested ? 'Verify and Create Account' : 'Send Verification Code')}
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
            <button
              type="button"
              onClick={() => switchStep('signup-profile')}
              className="text-slate-500 transition hover:text-cyan-300"
            >
              Don&apos;t have an account? Create one
            </button>
          </div>
          </section>

          <section className="hidden lg:flex rounded-3xl border border-cyan-900/40 bg-slate-950/55 backdrop-blur-xl p-10 shadow-[0_30px_80px_rgba(8,15,30,0.45)] min-h-[760px] overflow-hidden relative">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(56,189,248,0.12),transparent_30%),radial-gradient(circle_at_bottom_left,rgba(59,130,246,0.12),transparent_30%)]" />
          <div className="relative flex h-full w-full flex-col justify-between">
            <div className="relative flex h-full flex-col justify-between">
              <div className="max-w-3xl">
                <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan-400 to-blue-600 shadow-lg shadow-cyan-500/20 mb-6">
                  <Shield className="w-8 h-8 text-white" />
                </div>
                <p className="mb-4 text-[1.55rem] font-extrabold uppercase tracking-[0.24em] text-cyan-200">
                  SECA
                </p>
              </div>

              <div className="relative mt-6 min-h-[440px]">
                {featureSlides.map((slide, index) => (
                  <div
                    key={slide.eyebrow}
                    className={`absolute inset-0 grid items-center gap-10 xl:grid-cols-[1.2fr_0.8fr] transition-all duration-700 ease-out ${
                      index === activeSlide
                        ? 'translate-x-0 opacity-100'
                        : index < activeSlide
                          ? '-translate-x-8 opacity-0 pointer-events-none'
                          : 'translate-x-8 opacity-0 pointer-events-none'
                    }`}
                  >
                    <div className="max-w-2xl pr-4">
                      <div className={`inline-flex rounded-full border border-white/10 bg-gradient-to-r ${slide.accent} px-4 py-1.5 text-xs font-medium uppercase tracking-[0.22em] text-cyan-200`}>
                        {slide.eyebrow}
                      </div>
                      <h1 className="mt-6 text-[2.7rem] font-bold leading-[1.1] text-white 2xl:text-5xl">
                        {slide.title}
                      </h1>
                      <p className="mt-5 max-w-xl text-[0.98rem] leading-8 text-slate-400">
                        {slide.description}
                      </p>
                      <div className="mt-8 grid gap-3 sm:grid-cols-3">
                        {slide.points.map((point) => (
                          <div
                            key={point.label}
                            className="rounded-2xl border border-slate-800 bg-slate-900/65 px-4 py-4 text-slate-200 shadow-[0_10px_25px_rgba(2,6,23,0.18)]"
                          >
                            <div className="flex items-start gap-3">
                              <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border border-cyan-500/15 bg-cyan-500/10 text-cyan-300">
                                {point.icon}
                              </div>
                              <p className="text-[0.94rem] font-semibold leading-6 text-slate-200">
                                {point.label}
                              </p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="relative flex items-center justify-center">
                      <div className={`absolute h-72 w-72 rounded-full bg-gradient-to-br ${slide.accent} blur-3xl`} />
                      <div className="absolute h-[22rem] w-[22rem] rounded-full border border-slate-800/70" />
                      <div className="absolute h-[17rem] w-[17rem] rounded-full border border-dashed border-slate-700/80" />
                      <div className="absolute -left-2 top-8 h-3 w-3 rounded-full bg-cyan-400/80" />
                      <div className="absolute right-10 top-3 h-2.5 w-2.5 rounded-full border border-cyan-400/50" />
                      <div className="absolute bottom-8 left-10 h-4 w-4 rounded-full border border-cyan-400/35" />
                      <div className="relative flex max-w-[280px] flex-col items-center text-center">
                        <div className="mb-5 flex h-20 w-20 items-center justify-center rounded-3xl border border-cyan-500/20 bg-cyan-500/10 shadow-[0_10px_30px_rgba(34,211,238,0.08)]">
                          {slide.icon}
                        </div>
                        <p className="max-w-[210px] text-xl font-semibold text-white">{slide.eyebrow}</p>
                        <p className="mt-3 max-w-[250px] text-sm leading-7 text-slate-400">
                          Focused visibility on one important part of the platform.
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              <div className="relative mt-8 flex items-center justify-center">
                <div className="flex gap-2">
                  {featureSlides.map((slide, index) => (
                    <button
                      key={slide.eyebrow}
                      type="button"
                      onClick={() => setActiveSlide(index)}
                      className={`h-2.5 rounded-full transition-all duration-300 ${
                        index === activeSlide ? 'w-10 bg-cyan-400' : 'w-2.5 bg-slate-600 hover:bg-slate-500'
                      }`}
                      aria-label={`Show ${slide.eyebrow}`}
                    />
                  ))}
                </div>
              </div>
            </div>
          </div>
          </section>
        </div>

        <div className="mt-5 flex flex-col items-center justify-between gap-3 rounded-2xl border border-slate-900/80 bg-slate-950/30 px-6 py-4 text-sm text-slate-500 backdrop-blur-sm md:flex-row">
          <p className="text-center md:text-left">
            Built by USTO-MB students in collaboration with Sonatrach Activity LQS Headquarters (LQS-ORAN).
          </p>
          <div className="flex flex-wrap items-center justify-center gap-x-5 gap-y-2">
            <a
              href="https://github.com/Kaddour-yazid/SECA"
              target="_blank"
              rel="noreferrer"
              className="transition hover:text-slate-300"
            >
              GitHub Repository
            </a>
            <a
              href="https://www.univ-usto.dz/"
              target="_blank"
              rel="noreferrer"
              className="transition hover:text-slate-300"
            >
              USTO-MB
            </a>
            <a
              href="https://sonatrach.com/"
              target="_blank"
              rel="noreferrer"
              className="transition hover:text-slate-300"
            >
              Sonatrach
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
