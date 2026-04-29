import { BookOpenCheck, ExternalLink, Eye, FileText, Gavel, Network } from 'lucide-react';
import { useLanguage } from '../contexts/LanguageContext';

type Copy = {
  title: string;
  subtitle: string;
  noticeTitle: string;
  noticeText: string;
  monitoredTitle: string;
  legalTitle: string;
    items: string[];
};

const copy: Record<'en' | 'fr' | 'ar', Copy> = {
  en: {
    title: 'SECA Policies',
    subtitle: 'Internal security notice for supervised professional use.',
    noticeTitle: 'User notice',
    noticeText:
      'SECA is intended for professional cybersecurity work. Group administrators may monitor activity within their authorized scope: scans performed, security verdicts, proxy/monitoring events, blocked domains and audit actions. This supervision is used for security, traceability and incident handling, not for unrestricted access to private content. Users should avoid personal browsing or submitting personal files through the monitored environment.',
    monitoredTitle: 'Data that may be processed',
    legalTitle: 'Legal references',
    items: [
      'Account identity, role, department and group',
      'File, URL, e-mail and hash scan history',
      'Threat scores, verdicts and technical indicators',
      'Audit logs and administrator actions',
      'Proxy/monitoring metadata when enabled',
      'Group-level activity visible to authorized administrators',
    ],
  },
  fr: {
    title: 'Politiques SECA',
    subtitle: 'Notice interne pour un usage professionnel supervise.',
    noticeTitle: 'Information utilisateur',
    noticeText:
      'SECA est destinee a un usage professionnel de cybersecurite. Les administrateurs de groupe peuvent superviser les activites relevant de leur perimetre autorise : scans effectues, verdicts de securite, evenements proxy/monitoring, domaines bloques et actions d audit. Cette supervision sert la securite, la tracabilite et le traitement des incidents, sans donner un acces illimite aux contenus prives. Les utilisateurs doivent eviter la navigation personnelle ou le depot de fichiers personnels dans l environnement supervise.',
    monitoredTitle: 'Donnees pouvant etre traitees',
    legalTitle: 'References legales',
    items: [
      'Identite du compte, role, departement et groupe',
      'Historique des scans fichier, URL, e-mail et hash',
      'Scores, verdicts et indicateurs techniques',
      'Journaux d audit et actions administrateur',
      'Metadonnees proxy/monitoring lorsque le module est active',
      'Activite du groupe visible par les administrateurs autorises',
    ],
  },
  ar: {
    title: 'سياسات SECA',
    subtitle: 'إشعار داخلي للاستخدام المهني الخاضع للإشراف.',
    noticeTitle: 'إشعار المستخدم',
    noticeText:
      'تم تصميم SECA للاستخدام المهني في مجال الأمن السيبراني. يمكن لمسؤولي المجموعة مراقبة النشاط داخل النطاق المصرح لهم به، مثل عمليات الفحص، أحكام السلامة، أحداث الوكيل والمراقبة، النطاقات المحجوبة وإجراءات التدقيق. هذا الإشراف مخصص للأمن والتتبع ومعالجة الحوادث، وليس للوصول غير المحدود إلى المحتوى الخاص. يجب على المستخدمين تجنب التصفح الشخصي أو إرسال ملفات شخصية داخل البيئة الخاضعة للمراقبة.',
    monitoredTitle: 'البيانات التي يمكن معالجتها',
    legalTitle: 'المراجع القانونية',
    items: [
      'هوية الحساب، الدور، القسم والمجموعة',
      'سجل فحص الملفات والروابط والبريد الإلكتروني والبصمات',
      'درجات التهديد، الأحكام والمؤشرات التقنية',
      'سجلات التدقيق وإجراءات المسؤول',
      'بيانات الوكيل والمراقبة عند تفعيلها',
      'نشاط المجموعة المرئي للمسؤولين المصرح لهم',
    ],
  },
};

const legalRefs = [
  {
    name: 'Loi n°18-07',
    text: 'Protection des personnes physiques dans le traitement des données à caractère personnel.',
    url: 'https://droit.mjustice.gov.dz/fr/content/protection-des-personnes-physiques-dans-le-traitement-des-donn%C3%A9es-%C3%A0-caract%C3%A8re-personnel',
  },
  {
    name: 'Loi n°25-11',
    text: 'Modification et complément de la Loi n°18-07 relative aux données personnelles.',
    url: 'https://plaintes.anpdp.dz/notice.php',
  },
  {
    name: 'Loi n°09-04',
    text: 'Prévention et lutte contre les infractions liées aux technologies de l’information et de la communication.',
    url: 'https://www.commerce.gov.dz/fr/reglementation/loi-n-deg-09-04',
  },
];

export function PoliciesView() {
  const { language } = useLanguage();
  const text = copy[language] || copy.en;
  const isArabic = language === 'ar';

  return (
    <div dir={isArabic ? 'rtl' : 'ltr'} className="flex-1 bg-slate-900 global-scroll p-4 sm:p-6 xl:p-8">
      <div className="mx-auto max-w-6xl space-y-6">
        <section className="rounded-3xl border border-slate-700 bg-slate-950/80 p-8 text-center shadow-2xl shadow-slate-950/40">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl border border-cyan-400/25 bg-cyan-500/10 text-cyan-300">
            <BookOpenCheck className="h-8 w-8" />
          </div>
          <p className="mt-5 text-xs font-semibold uppercase tracking-[0.28em] text-cyan-300">Policies</p>
          <h2 className="mt-2 text-3xl font-bold text-white">{text.title}</h2>
          <p className="mx-auto mt-3 max-w-2xl text-sm text-slate-400">{text.subtitle}</p>
        </section>

        <section className="grid grid-cols-1 gap-6 xl:grid-cols-[0.95fr_1.05fr]">
          <article className="rounded-2xl border border-slate-700 bg-slate-800/50 p-6">
            <div className="mb-4 flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-500/10 text-blue-300">
                <Eye className="h-5 w-5" />
              </div>
              <h3 className="text-xl font-semibold text-white">{text.noticeTitle}</h3>
            </div>
            <p className={`text-sm leading-7 text-slate-300 ${isArabic ? 'text-right' : ''}`}>{text.noticeText}</p>
          </article>

          <article className="rounded-2xl border border-slate-700 bg-slate-800/50 p-6">
            <div className="mb-4 flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-300">
                <Network className="h-5 w-5" />
              </div>
              <h3 className="text-xl font-semibold text-white">{text.monitoredTitle}</h3>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {text.items.map((item) => (
                <div key={item} className="rounded-xl border border-slate-700 bg-slate-950/50 px-4 py-3 text-sm text-slate-300">
                  {item}
                </div>
              ))}
            </div>
          </article>
        </section>

        <section className="rounded-2xl border border-slate-700 bg-slate-800/50 p-6">
          <div className="mb-6 text-center">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-300">
              <Gavel className="h-6 w-6" />
            </div>
            <h3 className="mt-3 text-xl font-semibold text-white">{text.legalTitle}</h3>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            {legalRefs.map((ref) => (
              <a
                key={ref.name}
                href={ref.url}
                target="_blank"
                rel="noreferrer"
                className="group rounded-2xl border border-slate-700 bg-slate-950/50 p-5 text-center transition hover:border-cyan-400/60 hover:bg-slate-950"
              >
                <FileText className="mx-auto h-6 w-6 text-cyan-300" />
                <p className="mt-3 font-semibold text-white">{ref.name}</p>
                <p className="mt-2 text-sm leading-6 text-slate-400">{ref.text}</p>
                <span className="mt-4 inline-flex items-center justify-center gap-2 rounded-full border border-cyan-400/20 px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300 transition group-hover:border-cyan-300/60">
                  Official text <ExternalLink className="h-3.5 w-3.5" />
                </span>
              </a>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
