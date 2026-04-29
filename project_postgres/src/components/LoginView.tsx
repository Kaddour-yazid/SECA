import { useEffect, useMemo, useState } from 'react';
import {
  ArrowLeft,
  BarChart3,
  Clock3,
  FileWarning,
  Fingerprint,
  Globe,
  History,
  Inbox,
  KeyRound,
  LayoutDashboard,
  Link2,
  Loader2,
  Lock,
  Mail,
  Radar,
  ShieldCheck,
  Shield,
  AlertTriangle,
  Building2,
  Workflow,
  Github,
  GraduationCap,
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

type AuthStep = 'login' | 'signup-profile' | 'signup-organization' | 'signup-verify' | 'reset-request' | 'reset-confirm';

type FeatureSlide = {
  eyebrow: string;
  title: string;
  description: string;
  points: { label: string; icon: JSX.Element }[];
  preview: JSX.Element;
  accent: string;
};

function FileScannerPreview() {
  return (
    <div className="w-full max-w-[340px] rounded-3xl border border-slate-800 bg-[#0c1324] p-4 shadow-[0_20px_60px_rgba(2,6,23,0.35)]">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.22em] text-cyan-300/80">File Scanner</p>
          <h4 className="mt-2 text-lg font-semibold text-white">invoice_update.exe</h4>
        </div>
        <div className="rounded-full border border-rose-500/30 bg-rose-500/10 px-3 py-1 text-xs font-semibold text-rose-200">
          High Risk
        </div>
      </div>
      <div className="mt-5 grid grid-cols-3 gap-3">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-3">
          <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">Score</p>
          <p className="mt-2 text-2xl font-bold text-white">89</p>
        </div>
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-3">
          <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">Type</p>
          <p className="mt-2 text-sm font-semibold text-slate-200">PE32</p>
        </div>
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-3">
          <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">SHA256</p>
          <p className="mt-2 truncate text-sm font-semibold text-slate-200">a93c...f12d</p>
        </div>
      </div>
      <div className="mt-4 space-y-2">
        {[
          { icon: <FileWarning className="h-4 w-4" />, label: 'Packed binary behavior detected' },
          { icon: <Radar className="h-4 w-4" />, label: 'Suspicious outbound execution pattern' },
          { icon: <ShieldCheck className="h-4 w-4" />, label: 'Signature mismatch with trusted publisher' },
        ].map((item) => (
          <div key={item.label} className="flex items-center gap-3 rounded-2xl border border-slate-800 bg-slate-900/55 px-3 py-2.5 text-sm text-slate-300">
            <span className="text-cyan-300">{item.icon}</span>
            {item.label}
          </div>
        ))}
      </div>
    </div>
  );
}

function UrlVerdictPreview() {
  return (
    <div className="w-full max-w-[340px] rounded-3xl border border-slate-800 bg-[#0c1324] p-4 shadow-[0_20px_60px_rgba(2,6,23,0.35)]">
      <div className="flex items-center gap-3 rounded-2xl border border-slate-800 bg-slate-900/70 px-4 py-3">
        <Globe className="h-5 w-5 text-sky-300" />
        <div className="min-w-0">
          <p className="truncate text-sm font-semibold text-white">secure-login-check.example.net</p>
          <p className="text-xs text-slate-500">URL verdict and heuristic analysis</p>
        </div>
      </div>
      <div className="mt-4 grid grid-cols-2 gap-3">
        <div className="rounded-2xl border border-amber-500/20 bg-amber-500/10 p-3">
          <p className="text-[11px] uppercase tracking-[0.18em] text-amber-200/70">Verdict</p>
          <p className="mt-2 text-lg font-bold text-amber-100">Suspicious</p>
        </div>
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-3">
          <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">Confidence</p>
          <p className="mt-2 text-lg font-bold text-white">74%</p>
        </div>
      </div>
      <div className="mt-4 space-y-2">
        {[
          'Credential-harvesting keywords in path',
          'Recent domain age with low trust footprint',
          'Similarity to protected login domains',
        ].map((label) => (
            <div key={label} className="flex items-center justify-between rounded-2xl border border-slate-800 bg-slate-900/55 px-3 py-2.5 text-sm text-slate-300">
              <span>{label}</span>
              <AlertTriangle className="h-4 w-4 text-amber-300" />
            </div>
          ))}
        </div>
      </div>
  );
}

function DashboardPreview() {
  return (
    <div className="w-full max-w-[340px] rounded-3xl border border-slate-800 bg-[#0c1324] p-4 shadow-[0_20px_60px_rgba(2,6,23,0.35)]">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.22em] text-indigo-300/80">Dashboard</p>
          <h4 className="mt-2 text-lg font-semibold text-white">Operational Summary</h4>
        </div>
        <LayoutDashboard className="h-5 w-5 text-indigo-300" />
      </div>
      <div className="mt-4 grid grid-cols-2 gap-3">
        {[
          ['Scans', '248'],
          ['Suspicious', '17'],
          ['Blocked', '9'],
          ['Active', '12'],
        ].map(([label, value]) => (
          <div key={label} className="rounded-2xl border border-slate-800 bg-slate-900/70 p-3">
            <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">{label}</p>
            <p className="mt-2 text-2xl font-bold text-white">{value}</p>
          </div>
        ))}
      </div>
      <div className="mt-4 rounded-2xl border border-slate-800 bg-slate-900/55 p-4">
        <div className="flex items-end gap-2">
          {[42, 58, 33, 74, 61, 80, 54].map((h, index) => (
            <div
              key={index}
              className="w-full rounded-t-md bg-gradient-to-t from-indigo-500 to-cyan-400/80"
              style={{ height: `${h}px` }}
            />
          ))}
        </div>
      </div>
    </div>
  );
}

function AuditPreview() {
  return (
    <div className="w-full max-w-[340px] rounded-3xl border border-slate-800 bg-[#0c1324] p-4 shadow-[0_20px_60px_rgba(2,6,23,0.35)]">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.22em] text-emerald-300/80">Audit Timeline</p>
          <h4 className="mt-2 text-lg font-semibold text-white">Recent Security Activity</h4>
        </div>
        <Inbox className="h-5 w-5 text-emerald-300" />
      </div>
      <div className="mt-4 space-y-3">
        {[
          ['22:14', 'URL scan completed', 'User action'],
          ['22:10', 'Proxy block rule updated', 'Admin action'],
          ['22:04', 'File verdict stored', 'System event'],
        ].map(([time, title, meta], index) => (
          <div key={title} className="flex gap-3 rounded-2xl border border-slate-800 bg-slate-900/55 px-3 py-3">
            <div className={`mt-1 h-2.5 w-2.5 rounded-full ${index === 1 ? 'bg-amber-300' : 'bg-emerald-300'}`} />
            <div className="min-w-0">
              <p className="text-sm font-semibold text-white">{title}</p>
              <p className="mt-1 text-xs text-slate-500">{time} · {meta}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

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
    preview: <FileScannerPreview />,
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
    preview: <UrlVerdictPreview />,
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
    preview: <DashboardPreview />,
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
    preview: <AuditPreview />,
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
    'Sécurité des Systèmes',
    'Sécurité Industrielle (OT)',
    'Sécurité Applicative & Gouvernance',
  ],
} as const;

const sexOptions = [
  { value: 'male', label: 'Male' },
  { value: 'female', label: 'Female' },
];

const signupStepLabels = ['Identity', 'Department', 'Verification'];

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

  const showOtp = (step === 'signup-verify' && signupOtpRequested) || step === 'reset-confirm';
  const showNewPassword = step === 'reset-confirm';
  const isSignupFlow = step === 'signup-profile' || step === 'signup-organization' || step === 'signup-verify';
  const signupStepIndex =
    step === 'signup-profile' ? 0 : step === 'signup-organization' ? 1 : step === 'signup-verify' ? 2 : 0;
  const signupGroups = signupDepartment ? departmentGroups[signupDepartment] : [];

  return (
    <div className="global-scroll visible-scrollbar flex h-screen min-h-screen items-start justify-center overflow-y-auto bg-[radial-gradient(circle_at_top,_rgba(34,211,238,0.18),_transparent_35%),linear-gradient(135deg,#08111f_0%,#0f172a_48%,#111827_100%)] p-3 sm:p-4 lg:items-center lg:p-6">
      <style>{`
        @keyframes fadeSlideIn {
          from {
            opacity: 0;
            transform: translateX(-10px);
          }
          to {
            opacity: 1;
            transform: translateX(0);
          }
        }
      `}</style>
      <div className="w-full max-w-[1520px] py-1 sm:py-2 lg:py-0">
        <div
          className={`grid items-stretch gap-6 transition-[grid-template-columns] duration-500 ease-[cubic-bezier(0.22,1,0.36,1)] ${
            isSignupFlow
              ? 'lg:grid-cols-[minmax(430px,1.15fr)_minmax(0,2.15fr)]'
              : 'lg:grid-cols-[minmax(360px,0.95fr)_minmax(0,2.45fr)]'
          }`}
        >
          <section className="visible-scrollbar flex min-h-0 max-h-[calc(100vh-1rem)] flex-col overflow-y-scroll rounded-3xl border border-slate-800/90 bg-slate-900/84 p-4 shadow-[0_24px_70px_rgba(8,15,30,0.45)] backdrop-blur-xl transition-all duration-500 ease-[cubic-bezier(0.22,1,0.36,1)] [scrollbar-gutter:stable] sm:max-h-[calc(100vh-1.5rem)] sm:p-6 lg:min-h-[760px] lg:max-h-none lg:overflow-visible lg:p-7">
            <div className="mb-6 flex items-start justify-between gap-4 transition-all duration-300 ease-out sm:mb-8">
              <div className="min-w-0">
                <p className="text-[0.68rem] font-semibold uppercase tracking-[0.34em] text-cyan-300/85">SECA</p>
                <p className="mt-3 text-[0.68rem] font-medium uppercase tracking-[0.28em] text-slate-500">
                  {isSignupFlow ? 'Verified access' : 'Verified access'}
                </p>
                <h2 className="mt-3 text-[2rem] font-semibold tracking-[-0.03em] text-white">{heading.title}</h2>
                <p className="mt-2 max-w-md text-sm leading-6 text-slate-400/85">{heading.subtitle}</p>
              </div>
              {step !== 'login' && (
                <button
                  type="button"
                  onClick={handleBackNavigation}
                  className="inline-flex shrink-0 items-center gap-2 rounded-xl border border-slate-700/80 px-3 py-2 text-xs font-medium text-slate-300 transition hover:border-slate-500 hover:text-white"
                >
                  <ArrowLeft className="h-4 w-4" />
                  Back
                </button>
              )}
            </div>

            <div className="mb-5 flex gap-2 transition-all duration-300 ease-out sm:mb-6">
              <button
                type="button"
                onClick={() => switchStep('login')}
                className={`flex-1 rounded-xl py-3 font-medium transition ${
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
                className={`flex-1 rounded-xl py-3 font-medium transition ${
                  isSignupFlow
                    ? 'bg-cyan-500 text-white shadow-lg shadow-cyan-500/20'
                    : 'bg-slate-950/40 text-slate-400 hover:text-white'
                }`}
              >
                Sign Up
              </button>
            </div>

            {isSignupFlow && (
              <div className="mb-5 rounded-2xl border border-slate-800 bg-slate-950/35 px-3 py-3 animate-[fadeSlideIn_320ms_ease-out] sm:mb-6 sm:px-4 sm:py-4">
                <div className="mb-3 h-1.5 overflow-hidden rounded-full bg-slate-800 sm:mb-4">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-cyan-400 to-blue-500 transition-all duration-500"
                    style={{ width: `${((signupStepIndex + 1) / signupStepLabels.length) * 100}%` }}
                  />
                </div>
                <div className="grid gap-2.5 sm:grid-cols-3 sm:gap-3">
                  {signupStepLabels.map((label, index) => (
                    <div
                      key={label}
                      className={`rounded-2xl border px-3 py-2.5 transition sm:py-3 ${
                        signupStepIndex === index
                          ? 'border-cyan-400/40 bg-cyan-500/10'
                          : signupStepIndex > index
                            ? 'border-cyan-900/60 bg-slate-900/70'
                            : 'border-slate-800 bg-slate-950/45'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <div
                          className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full border text-xs font-semibold ${
                            signupStepIndex >= index
                              ? 'border-cyan-400/40 bg-cyan-400/15 text-cyan-200'
                              : 'border-slate-700 text-slate-500'
                          }`}
                        >
                          {index + 1}
                        </div>
                        <div className="min-w-0">
                          <p className="text-[0.68rem] uppercase tracking-[0.2em] text-slate-500">Step {index + 1}</p>
                          <p className="mt-1 text-sm font-semibold text-slate-200">{label}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

              <form onSubmit={handleSubmit} className="flex min-h-0 flex-1 flex-col gap-4 pr-1 sm:pr-2">
              {step === 'login' && (
                <div className="animate-[fadeSlideIn_320ms_ease-out] space-y-4">
                  <div>
                    <label className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-slate-500">Email</label>
                    <div className="relative">
                      <Mail className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-500" />
                      <input
                        type="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        className="w-full rounded-xl border border-slate-700 bg-slate-950/60 py-3 pl-10 pr-4 text-white transition placeholder:text-slate-500 focus:border-transparent focus:outline-none focus:ring-2 focus:ring-cyan-500"
                        placeholder="your@email.com"
                        required
                        disabled={loading}
                      />
                    </div>
                  </div>

                  <div>
                    <label className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-slate-500">Password</label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-500" />
                      <input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        className="w-full rounded-xl border border-slate-700 bg-slate-950/60 py-3 pl-10 pr-4 text-white transition placeholder:text-slate-500 focus:border-transparent focus:outline-none focus:ring-2 focus:ring-cyan-500"
                        placeholder="Enter your password"
                        required
                        minLength={8}
                        disabled={loading}
                      />
                    </div>
                  </div>
                </div>
              )}

              {isSignupFlow && (
                <div className="min-h-0 overflow-hidden animate-[fadeSlideIn_320ms_ease-out]">
                  <div
                    className="flex transition-transform duration-500 ease-out"
                    style={{ transform: `translateX(-${signupStepIndex * 100}%)` }}
                  >
                    <div className="w-full shrink-0 space-y-4 pr-1">
                        <div className="grid gap-3 sm:grid-cols-2 sm:gap-4">
                        <div>
                          <label className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-slate-500">First name</label>
                          <input
                            type="text"
                            value={signupFirstName}
                            onChange={(e) => setSignupFirstName(e.target.value)}
                            className="w-full rounded-xl border border-slate-700 bg-slate-950/60 px-4 py-3 text-white transition placeholder:text-slate-500 focus:border-transparent focus:outline-none focus:ring-2 focus:ring-cyan-500"
                            placeholder="Your first name"
                            disabled={loading}
                          />
                        </div>
                        <div>
                          <label className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-slate-500">Last name</label>
                          <input
                            type="text"
                            value={signupLastName}
                            onChange={(e) => setSignupLastName(e.target.value)}
                            className="w-full rounded-xl border border-slate-700 bg-slate-950/60 px-4 py-3 text-white transition placeholder:text-slate-500 focus:border-transparent focus:outline-none focus:ring-2 focus:ring-cyan-500"
                            placeholder="Your last name"
                            disabled={loading}
                          />
                        </div>
                      </div>
                      <div>
                        <label className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-slate-500">Email</label>
                        <div className="relative">
                          <Mail className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-500" />
                          <input
                            type="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            className="w-full rounded-xl border border-slate-700 bg-slate-950/60 py-3 pl-10 pr-4 text-white transition placeholder:text-slate-500 focus:border-transparent focus:outline-none focus:ring-2 focus:ring-cyan-500"
                            placeholder="your@email.com"
                            disabled={loading}
                          />
                        </div>
                      </div>
                      <div>
                        <label className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-slate-500">Sex</label>
                        <div className="grid grid-cols-2 gap-2.5 sm:gap-3">
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
                        <label className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-slate-500">Department</label>
                        <div className="grid gap-2.5 sm:grid-cols-3">
                          {(['RXS', 'SLM', 'SSI'] as const).map((department) => (
                            <button
                              key={department}
                              type="button"
                              onClick={() => {
                                setSignupDepartment(department);
                                setSignupGroup('');
                              }}
                              disabled={loading}
                              className={`rounded-2xl border px-3.5 py-3.5 text-left transition ${
                                signupDepartment === department
                                  ? 'border-cyan-400/40 bg-cyan-500/10 text-cyan-100 shadow-[0_12px_30px_rgba(34,211,238,0.08)]'
                                  : 'border-slate-700 bg-slate-950/50 text-slate-300 hover:border-slate-500 hover:bg-slate-900/70'
                              }`}
                            >
                              <p className="text-sm font-semibold">{department}</p>
                              <p className="mt-1 text-[11px] leading-5 text-slate-500">
                                {department === 'RXS' && 'Infrastructure and systems'}
                                {department === 'SLM' && 'Business solutions and delivery'}
                                {department === 'SSI' && 'Information security'}
                              </p>
                            </button>
                          ))}
                        </div>
                      </div>
                      <div>
                        <label className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-slate-500">Group</label>
                        <div className="max-h-[140px] space-y-2 overflow-y-auto rounded-2xl border border-slate-800 bg-slate-950/35 p-2 pr-1.5 sm:max-h-[176px]">
                          {!signupDepartment ? (
                            <div className="rounded-xl border border-dashed border-slate-800 bg-slate-950/40 px-4 py-5 text-sm text-slate-500">
                              Select a department first to unlock its groups.
                            </div>
                          ) : (
                            signupGroups.map((groupName) => (
                              <button
                                key={groupName}
                                type="button"
                                onClick={() => setSignupGroup(groupName)}
                                disabled={loading}
                                className={`w-full rounded-xl border px-4 py-2.5 text-left transition ${
                                  signupGroup === groupName
                                    ? 'border-cyan-400/40 bg-cyan-500/10 text-cyan-100'
                                    : 'border-slate-800 bg-slate-950/50 text-slate-300 hover:border-slate-600 hover:bg-slate-900/70'
                                }`}
                              >
                                <span className="block text-sm font-medium leading-5">{groupName}</span>
                              </button>
                            ))
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="w-full shrink-0 space-y-4 pr-1">
                      <div className="grid gap-3 sm:grid-cols-2 sm:gap-4">
                        <div>
                          <label className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-slate-500">Create password</label>
                          <div className="relative">
                            <Lock className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-500" />
                            <input
                              type="password"
                              value={password}
                              onChange={(e) => setPassword(e.target.value)}
                              className="w-full rounded-xl border border-slate-700 bg-slate-950/60 py-3 pl-10 pr-4 text-white transition placeholder:text-slate-500 focus:border-transparent focus:outline-none focus:ring-2 focus:ring-cyan-500"
                              placeholder="Minimum 8 characters"
                              minLength={8}
                              disabled={loading || signupOtpRequested}
                            />
                          </div>
                        </div>
                        <div>
                          <label className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-slate-500">Confirm password</label>
                          <div className="relative">
                            <Lock className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-500" />
                            <input
                              type="password"
                              value={confirmPassword}
                              onChange={(e) => setConfirmPassword(e.target.value)}
                              className="w-full rounded-xl border border-slate-700 bg-slate-950/60 py-3 pl-10 pr-4 text-white transition placeholder:text-slate-500 focus:border-transparent focus:outline-none focus:ring-2 focus:ring-cyan-500"
                              placeholder="Repeat your password"
                              minLength={8}
                              disabled={loading || signupOtpRequested}
                            />
                          </div>
                        </div>
                      </div>

                      {signupOtpRequested && (
                        <div>
                          <label className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-slate-500">One-Time Code</label>
                          <div className="relative">
                            <KeyRound className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-500" />
                            <input
                              type="text"
                              value={otpCode}
                              onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                              className="w-full rounded-xl border border-slate-700 bg-slate-950/60 py-3 pl-10 pr-4 tracking-[0.35em] text-white transition placeholder:text-slate-500 focus:border-transparent focus:outline-none focus:ring-2 focus:ring-cyan-500"
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
                  <label className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-slate-500">Email</label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-500" />
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="w-full rounded-xl border border-slate-700 bg-slate-950/60 py-3 pl-10 pr-4 text-white transition placeholder:text-slate-500 focus:border-transparent focus:outline-none focus:ring-2 focus:ring-cyan-500"
                      placeholder="your@email.com"
                      required
                      disabled={loading}
                    />
                  </div>
                </div>
              )}

              {showOtp && !isSignupFlow && (
                <div>
                  <label className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-slate-500">One-Time Code</label>
                  <div className="relative">
                    <KeyRound className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-500" />
                    <input
                      type="text"
                      value={otpCode}
                      onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      className="w-full rounded-xl border border-slate-700 bg-slate-950/60 py-3 pl-10 pr-4 tracking-[0.35em] text-white transition placeholder:text-slate-500 focus:border-transparent focus:outline-none focus:ring-2 focus:ring-cyan-500"
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
                  <label className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-slate-500">New Password</label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-500" />
                    <input
                      type="password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      className="w-full rounded-xl border border-slate-700 bg-slate-950/60 py-3 pl-10 pr-4 text-white transition placeholder:text-slate-500 focus:border-transparent focus:outline-none focus:ring-2 focus:ring-cyan-500"
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
                className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 py-3 font-semibold text-white transition hover:from-cyan-600 hover:to-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {loading ? (
                  <>
                    <Loader2 className="h-5 w-5 animate-spin" />
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

            <div className="mt-4 flex flex-col items-start gap-3 pt-4 text-sm sm:mt-6 sm:flex-row sm:items-center sm:justify-between sm:pt-6">
              <button
                type="button"
                onClick={() => switchStep(isSignupFlow ? 'login' : step === 'reset-request' || step === 'reset-confirm' ? 'login' : 'reset-request')}
                className="text-slate-500 transition hover:text-cyan-300"
              >
                {isSignupFlow
                  ? 'Do you want to sign in?'
                  : step === 'reset-request' || step === 'reset-confirm'
                    ? 'Back to sign in'
                    : 'Forgot password?'}
              </button>
              <button
                type="button"
                onClick={() => switchStep('signup-profile')}
                className={`transition hover:text-cyan-300 ${isSignupFlow ? 'pointer-events-none opacity-0' : 'text-slate-500'}`}
              >
                Don&apos;t have an account? Create one
              </button>
            </div>
          </section>

          <section className="relative hidden min-h-[760px] overflow-hidden rounded-3xl border border-cyan-900/40 bg-slate-950/55 p-10 shadow-[0_30px_80px_rgba(8,15,30,0.45)] backdrop-blur-xl lg:flex">
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(56,189,248,0.12),transparent_30%),radial-gradient(circle_at_bottom_left,rgba(59,130,246,0.12),transparent_30%)]" />
            <div className="relative flex h-full w-full flex-col justify-between">
              <div className="relative flex h-full flex-col justify-between">
                <div className="max-w-3xl">
                  <div className="mb-6 inline-flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-400 to-blue-600 shadow-lg shadow-cyan-500/20">
                    <Shield className="h-8 w-8 text-white" />
                  </div>
                  <p className="text-[2rem] font-extrabold uppercase tracking-[0.24em] text-cyan-200">SECA</p>
                </div>

                <div className="relative mt-4 min-h-[430px]">
                  {featureSlides.map((slide, index) => (
                    <div
                      key={slide.eyebrow}
                      className={`absolute inset-0 grid items-center gap-12 xl:grid-cols-[1.1fr_0.9fr] transition-all duration-700 ease-out ${
                        index === activeSlide
                          ? 'translate-x-0 opacity-100'
                          : index < activeSlide
                            ? '-translate-x-8 pointer-events-none opacity-0'
                            : 'translate-x-8 pointer-events-none opacity-0'
                      }`}
                    >
                      <div className="max-w-[42rem] pr-2">
                        <div className={`inline-flex rounded-full border border-white/10 bg-gradient-to-r ${slide.accent} px-4 py-1.5 text-[0.68rem] font-semibold uppercase tracking-[0.22em] text-cyan-200`}>
                          {slide.eyebrow}
                        </div>
                        <h1 className="mt-5 max-w-[40rem] text-[2.1rem] font-semibold leading-[1.08] tracking-[-0.04em] text-white 2xl:text-[2.8rem]">
                          {slide.title}
                        </h1>
                        <p className="mt-4 max-w-[36rem] text-[0.92rem] leading-6 text-slate-400/90">{slide.description}</p>
                        <div className="mt-6 grid gap-3 sm:grid-cols-3">
                          {slide.points.map((point) => (
                            <div
                              key={point.label}
                              className="rounded-2xl border border-slate-800 bg-slate-900/65 px-4 py-3.5 text-slate-200 shadow-[0_10px_25px_rgba(2,6,23,0.18)]"
                            >
                              <div className="flex items-start gap-3">
                                <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border border-cyan-500/15 bg-cyan-500/10 text-cyan-300">
                                  {point.icon}
                                </div>
                                <p className="text-[0.9rem] font-semibold leading-6 text-slate-200">{point.label}</p>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div className="relative flex items-center justify-center scale-[0.94] xl:scale-100">
                        <div className={`absolute h-80 w-80 rounded-full bg-gradient-to-br ${slide.accent} blur-3xl`} />
                        <div className="absolute h-[24rem] w-[24rem] rounded-full border border-slate-800/70" />
                        <div className="absolute h-[19rem] w-[19rem] rounded-full border border-dashed border-slate-700/80" />
                        <div className="absolute -left-2 top-10 h-3 w-3 rounded-full bg-cyan-400/80" />
                        <div className="absolute right-8 top-4 h-2.5 w-2.5 rounded-full border border-cyan-400/50" />
                        <div className="absolute bottom-10 left-12 h-4 w-4 rounded-full border border-cyan-400/35" />
                        <div className="relative flex w-full items-center justify-center">{slide.preview}</div>
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
              className="inline-flex items-center gap-2 transition hover:text-slate-300"
            >
              <Github className="h-3.5 w-3.5 text-slate-400" />
              GitHub Repository
            </a>
            <a
              href="https://www.univ-usto.dz/en/"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 transition hover:text-slate-300"
            >
              <GraduationCap className="h-3.5 w-3.5 text-slate-400" />
              USTO-MB
            </a>
            <a
              href="https://sonatrach.com/fr/"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 transition hover:text-slate-300"
            >
              <Building2 className="h-3.5 w-3.5 text-slate-400" />
              Sonatrach
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}



