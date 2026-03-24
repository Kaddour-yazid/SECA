import {
  createContext,
  ReactNode,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';

export type Language = 'en' | 'fr' | 'ar';

type LanguageContextType = {
  language: Language;
  isRtl: boolean;
  setLanguage: (language: Language) => void;
  t: (key: string, fallback?: string) => string;
  translateText: (text: string) => string;
};

type KeyDictionary = Record<string, Record<Language, string>>;
type LiteralDictionary = Record<string, Partial<Record<Exclude<Language, 'en'>, string>>>;

const STORAGE_KEY = 'seca-language';

const keyTranslations: KeyDictionary = {
  'settings.button': {
    en: 'Parameters',
    fr: 'Parametres',
    ar: 'الاعدادات',
  },
  'settings.title': {
    en: 'Parameters',
    fr: 'Parametres',
    ar: 'الاعدادات',
  },
  'settings.subtitle': {
    en: 'Choose the interface language.',
    fr: "Choisissez la langue de l'interface.",
    ar: 'اختر لغة الواجهة.',
  },
  'settings.language': {
    en: 'Language',
    fr: 'Langue',
    ar: 'اللغة',
  },
  'settings.appearance': {
    en: 'Appearance',
    fr: 'Apparence',
    ar: 'المظهر',
  },
  'settings.account': {
    en: 'Account',
    fr: 'Compte',
    ar: 'الحساب',
  },
  'settings.logout': {
    en: 'Logout',
    fr: 'Se deconnecter',
    ar: 'تسجيل الخروج',
  },
  'settings.close': {
    en: 'Close',
    fr: 'Fermer',
    ar: 'اغلاق',
  },
  'language.en': {
    en: 'English',
    fr: 'English',
    ar: 'English',
  },
  'language.fr': {
    en: 'Francais',
    fr: 'Francais',
    ar: 'Francais',
  },
  'language.ar': {
    en: 'Arabic',
    fr: 'Arabe',
    ar: 'العربية',
  },
};

const literalTranslations: LiteralDictionary = {
  Parameters: { fr: 'Parametres', ar: 'الاعدادات' },
  'Manage your language, appearance, account, and session from one place.': { fr: 'Gerez votre langue, apparence, compte et session depuis un seul endroit.', ar: 'ادِر لغتك ومظهر الواجهة وحسابك وجلستك من مكان واحد.' },
  'Language Settings': { fr: 'Parametres de langue', ar: 'اعدادات اللغة' },
  'Appearance Settings': { fr: "Parametres d'apparence", ar: 'اعدادات المظهر' },
  'Switch between light and dark mode.': { fr: 'Basculez entre le mode clair et le mode sombre.', ar: 'بدل بين الوضع الفاتح والوضع الداكن.' },
  'Review your current account information.': { fr: 'Consultez les informations de votre compte actuel.', ar: 'راجع معلومات حسابك الحالي.' },
  Logout: { fr: 'Se deconnecter', ar: 'تسجيل الخروج' },
  'End the current session securely.': { fr: 'Terminez la session en cours en toute securite.', ar: 'انهِ الجلسة الحالية بشكل آمن.' },
  'Select the language used across the SECA interface.': { fr: "Selectionnez la langue utilisee dans l'interface SECA.", ar: 'اختر اللغة المستخدمة في واجهة SECA.' },
  'Choose how the platform should look on this device.': { fr: "Choisissez l'apparence de la plateforme sur cet appareil.", ar: 'اختر كيف يبدو النظام على هذا الجهاز.' },
  'Use a brighter interface.': { fr: 'Utiliser une interface plus claire.', ar: 'استخدم واجهة اكثر سطوعا.' },
  'Use a darker interface.': { fr: 'Utiliser une interface plus sombre.', ar: 'استخدم واجهة ادكن.' },
  'Current account information for the active session.': { fr: 'Informations du compte actif pour la session en cours.', ar: 'معلومات الحساب النشط للجلسة الحالية.' },
  Role: { fr: 'Role', ar: 'الدور' },
  'More account options will be added here.': { fr: "D'autres options de compte seront ajoutees ici.", ar: 'ستضاف خيارات حساب اخرى هنا.' },
  'For now, this section shows the active account and lets you manage language, theme, and logout from this page.': { fr: 'Pour le moment, cette section affiche le compte actif et vous permet de gerer la langue, le theme et la deconnexion depuis cette page.', ar: 'حاليا، يعرض هذا القسم الحساب النشط ويتيح لك ادارة اللغة والمظهر وتسجيل الخروج من هذه الصفحة.' },
  Appearance: { fr: 'Apparence', ar: 'المظهر' },
  'Open Parameters to change language, theme, account, or logout.': { fr: 'Ouvrez Parametres pour changer la langue, le theme, le compte ou la deconnexion.', ar: 'افتح الاعدادات لتغيير اللغة والمظهر والحساب او تسجيل الخروج.' },
  Dashboard: { fr: 'Tableau de bord', ar: 'لوحة التحكم' },
  'File Scanner': { fr: 'Analyseur de fichiers', ar: 'فاحص الملفات' },
  'URL Scanner': { fr: "Analyseur d'URL", ar: 'فاحص الروابط' },
  'Hash Checker': { fr: 'Verificateur de hash', ar: 'فاحص البصمة' },
  Monitoring: { fr: 'Surveillance', ar: 'المراقبة' },
  'Audit Logs': { fr: "Journaux d'audit", ar: 'سجلات التدقيق' },
  'Access Control': { fr: "Controle d'acces", ar: 'التحكم في الوصول' },
  'Security Analyzer': { fr: 'Analyseur de securite', ar: 'محلل الامان' },
  Admin: { fr: 'Admin', ar: 'مسؤول' },
  User: { fr: 'Utilisateur', ar: 'مستخدم' },
  'Light Mode': { fr: 'Mode clair', ar: 'الوضع الفاتح' },
  'Dark Mode': { fr: 'Mode sombre', ar: 'الوضع الداكن' },
  'Sign Out': { fr: 'Se deconnecter', ar: 'تسجيل الخروج' },
  'SECA Platform': { fr: 'Plateforme SECA', ar: 'منصة SECA' },
  'SECA platform access': { fr: 'Connexion a la plateforme SECA', ar: 'الدخول الى منصة SECA' },
  'Secure access': { fr: 'Acces securise', ar: 'وصول آمن' },
  Restricted: { fr: 'Restreint', ar: 'مقيد' },
  Active: { fr: 'Actif', ar: 'نشط' },
  Review: { fr: 'Revue', ar: 'مراجعة' },
  Logged: { fr: 'Journalise', ar: 'مسجل' },
  'Security notice': { fr: 'Notice de securite', ar: 'ملاحظة امنية' },
  'SECA activity preview': { fr: "Apercu d'activite SECA", ar: 'معاينة نشاط SECA' },
  'Monitoring and audit workflows': { fr: "Flux de supervision et d'audit", ar: 'مسارات المراقبة والتدقيق' },
  'URL scan queued': { fr: "Scan d'URL en attente", ar: 'فحص الرابط في الانتظار' },
  'Gateway policy hit': { fr: 'Regle passerelle declenchee', ar: 'تم تفعيل سياسة البوابة' },
  'Audit trail synced': { fr: "Piste d'audit synchronisee", ar: 'تمت مزامنة سجل التدقيق' },
  'Restricted system access': { fr: 'Acces systeme restreint', ar: 'وصول النظام مقيد' },
  'Authorized personnel only': { fr: 'Personnel autorise uniquement', ar: 'للمخولين فقط' },
  'Internal system': { fr: 'Systeme interne', ar: 'نظام داخلي' },
  'Internal security analysis environment': { fr: "Environnement interne d'analyse de securite", ar: 'بيئة داخلية لتحليل الامن' },
  'Restricted access to SECA analysis, supervision, and audit workflows.': { fr: "Acces restreint aux flux SECA d'analyse, de supervision et d'audit.", ar: 'وصول مقيد الى مسارات SECA الخاصة بالتحليل والمراقبة والتدقيق.' },
  'Internal security operations portal': { fr: 'Portail interne des operations de securite', ar: 'بوابة داخلية لعمليات الامن' },
  'Internal security operations portal for scanning, monitoring, and audit workflows.': { fr: "Plateforme interne d'analyse, de supervision et d'audit en cybersecurite.", ar: 'منصة داخلية لعمليات الفحص والمراقبة والتدقيق الامني.' },
  'Account Security': { fr: 'Securite du compte', ar: 'امان الحساب' },
  'Create your SECA account': { fr: 'Creer votre compte SECA', ar: 'انشئ حساب SECA الخاص بك' },
  'Create Account': { fr: 'Creer un compte', ar: 'انشاء حساب' },
  'Verify your email': { fr: 'Verifiez votre email', ar: 'تحقق من بريدك الالكتروني' },
  'Verify Email': { fr: "Verifier l'email", ar: 'تأكيد البريد الالكتروني' },
  'Recover access': { fr: "Recuperer l'acces", ar: 'استعادة الوصول' },
  'Recover Password': { fr: 'Recuperer le mot de passe', ar: 'استعادة كلمة المرور' },
  'Set a new password': { fr: 'Definir un nouveau mot de passe', ar: 'تعيين كلمة مرور جديدة' },
  'Set New Password': { fr: 'Definir un nouveau mot de passe', ar: 'تعيين كلمة مرور جديدة' },
  'Welcome back': { fr: 'Bon retour', ar: 'مرحبا بعودتك' },
  'Sign In': { fr: 'Se connecter', ar: 'تسجيل الدخول' },
  'Sign Up': { fr: "S'inscrire", ar: 'انشاء حساب' },
  Back: { fr: 'Retour', ar: 'رجوع' },
  Email: { fr: 'Email', ar: 'البريد الالكتروني' },
  Password: { fr: 'Mot de passe', ar: 'كلمة المرور' },
  'Create Password': { fr: 'Creer un mot de passe', ar: 'انشاء كلمة مرور' },
  'One-Time Code': { fr: 'Code unique', ar: 'رمز لمرة واحدة' },
  'New Password': { fr: 'Nouveau mot de passe', ar: 'كلمة مرور جديدة' },
  'Send Verification Code': { fr: 'Envoyer le code de verification', ar: 'ارسال رمز التحقق' },
  'Verify and Create Account': { fr: 'Verifier et creer le compte', ar: 'تحقق وانشئ الحساب' },
  'Send Reset Code': { fr: 'Envoyer le code de reinitialisation', ar: 'ارسال رمز اعادة التعيين' },
  'Update Password': { fr: 'Mettre a jour le mot de passe', ar: 'تحديث كلمة المرور' },
  'Back to sign in': { fr: 'Retour a la connexion', ar: 'العودة لتسجيل الدخول' },
  'Forgot password?': { fr: 'Mot de passe oublie ?', ar: 'هل نسيت كلمة المرور؟' },
  'Create one here': { fr: 'Creez-en un ici', ar: 'انشئ واحدا هنا' },
  'Sign in here': { fr: 'Connectez-vous ici', ar: 'سجل الدخول هنا' },
  "Don't have an account?": { fr: "Vous n'avez pas de compte ?", ar: 'ليس لديك حساب؟' },
  'Already have an account?': { fr: 'Vous avez deja un compte ?', ar: 'لديك حساب بالفعل؟' },
  'Show password': { fr: 'Afficher le mot de passe', ar: 'اظهار كلمة المرور' },
  'Hide password': { fr: 'Masquer le mot de passe', ar: 'اخفاء كلمة المرور' },
  'Processing...': { fr: 'Traitement...', ar: 'جار المعالجة...' },
  'Login successful. Redirecting...': { fr: 'Connexion reussie. Redirection...', ar: 'تم تسجيل الدخول بنجاح. جار التحويل...' },
  'Email verified. You can now sign in with your password.': { fr: 'Email verifie. Vous pouvez maintenant vous connecter avec votre mot de passe.', ar: 'تم التحقق من البريد. يمكنك الان تسجيل الدخول بكلمة المرور.' },
  'Password updated. Sign in with the new password.': { fr: 'Mot de passe mis a jour. Connectez-vous avec le nouveau mot de passe.', ar: 'تم تحديث كلمة المرور. سجل الدخول بكلمة المرور الجديدة.' },
  'Authentication failed': { fr: "Echec de l'authentification", ar: 'فشلت المصادقة' },
  'your@email.com': { fr: 'votre@email.com', ar: 'your@email.com' },
  'Minimum 8 characters': { fr: '8 caracteres minimum', ar: '8 احرف على الاقل' },
  'Platform scope': { fr: 'Portee de la plateforme', ar: 'نطاق المنصة' },
  'Static and dynamic scan workflows': { fr: 'Flux de scan statique et dynamique', ar: 'مسارات فحص ثابتة وديناميكية' },
  'Gateway supervision and audit visibility': { fr: 'Supervision de passerelle et visibilite audit', ar: 'اشراف على البوابة ورؤية سجلات التدقيق' },
  'Internal operations only': { fr: 'Operations internes uniquement', ar: 'للاستخدام الداخلي فقط' },
  'Static and sandbox inspection': { fr: 'Inspection statique et sandbox', ar: 'فحص ثابت وداخل الساندبوكس' },
  'Reputation and content controls': { fr: 'Controles de reputation et de contenu', ar: 'ضوابط السمعة والمحتوى' },
  'Fast verdict against known indicators': { fr: 'Verdict rapide contre les indicateurs connus', ar: 'حكم سريع مقابل المؤشرات المعروفة' },
  'Traceability for monitored actions': { fr: 'Traçabilite des actions supervisees', ar: 'قابلية تتبع الاجراءات الخاضعة للمراقبة' },
  'Security analysis, monitoring, and access control from one workspace.': { fr: 'Analyse de securite, surveillance et controle d acces depuis un seul espace de travail.', ar: 'تحليل الامان والمراقبة والتحكم في الوصول من مساحة عمل واحدة.' },
  'Multi-layer threat analysis': { fr: 'Analyse des menaces multi-couches', ar: 'تحليل التهديدات متعدد الطبقات' },
  'Analyze files, URLs, hashes, and emails with unified verdicts and detailed reports.': { fr: 'Analysez les fichiers, URL, hashes et emails avec des verdicts unifies et des rapports detailles.', ar: 'حلل الملفات والروابط والبصمات والبريد مع نتائج موحدة وتقارير مفصلة.' },
  'Monitoring and enforcement': { fr: 'Surveillance et application', ar: 'المراقبة والتنفيذ' },
  'Track gateway activity, review audit logs, and manage policy decisions from the same dashboard.': { fr: 'Suivez l activite de la passerelle, consultez les journaux d audit et gerez les politiques depuis le meme tableau de bord.', ar: 'تابع نشاط البوابة وراجع سجلات التدقيق وادِر السياسات من نفس اللوحة.' },
  'Verify ownership of your email before the account is created.': { fr: "Verifiez la propriete de votre email avant la creation du compte.", ar: 'تحقق من ملكية بريدك قبل انشاء الحساب.' },
  'Authenticate to access scanning and monitoring tools.': { fr: "Authentifiez-vous pour acceder aux outils de scan et de supervision.", ar: 'قم بالمصادقة للوصول الى ادوات الفحص والمراقبة.' },
  'Enter your email and password to continue.': { fr: 'Entrez votre email et votre mot de passe pour continuer.', ar: 'ادخل بريدك وكلمة المرور للمتابعة.' },
  'Start with your work email and a secure password.': { fr: 'Commencez avec votre email professionnel et un mot de passe securise.', ar: 'ابدأ ببريد العمل وكلمة مرور آمنة.' },
  'Create your account to get started.': { fr: 'Creez votre compte pour commencer.', ar: 'انشئ حسابك للبدء.' },
  'Enter the verification code sent to your inbox.': { fr: 'Entrez le code de verification envoye dans votre boite mail.', ar: 'ادخل رمز التحقق المرسل الى بريدك.' },
  'Enter the one-time code sent to your inbox.': { fr: 'Entrez le code unique envoye dans votre boite mail.', ar: 'ادخل الرمز المرسل الى بريدك.' },
  'Enter the code sent to your email.': { fr: 'Entrez le code envoye a votre email.', ar: 'ادخل الرمز المرسل الى بريدك الالكتروني.' },
  'Request a reset code for your SECA account.': { fr: 'Demandez un code de reinitialisation pour votre compte SECA.', ar: 'اطلب رمز اعادة تعيين لحساب SECA الخاص بك.' },
  'Reset your password securely.': { fr: 'Reinitialisez votre mot de passe en toute securite.', ar: 'اعد تعيين كلمة المرور بشكل آمن.' },
  'Request a reset code for your existing user account.': { fr: 'Demandez un code de reinitialisation pour votre compte existant.', ar: 'اطلب رمز اعادة تعيين لحسابك الحالي.' },
  'Choose a new password to restore access.': { fr: "Choisissez un nouveau mot de passe pour restaurer l'acces.", ar: 'اختر كلمة مرور جديدة لاستعادة الوصول.' },
  'Use the reset code to assign a new password.': { fr: 'Utilisez le code de reinitialisation pour definir un nouveau mot de passe.', ar: 'استخدم رمز اعادة التعيين لتحديد كلمة مرور جديدة.' },
  'File scanning': { fr: 'Scan de fichiers', ar: 'فحص الملفات' },
  'URL analysis': { fr: "Analyse d'URL", ar: 'تحليل الروابط' },
  'Hash verification': { fr: 'Verification de hash', ar: 'التحقق من البصمة' },
  'Admin audit': { fr: 'Audit administrateur', ar: 'تدقيق المسؤول' },
  'Internal use only': { fr: 'Usage interne uniquement', ar: 'للاستخدام الداخلي فقط' },
  'Enter the reset code and choose a new password.': { fr: 'Entrez le code de reinitialisation et choisissez un nouveau mot de passe.', ar: 'ادخل رمز اعادة التعيين واختر كلمة مرور جديدة.' },
  'Access your SECA workspace with your verified account.': { fr: 'Accedez a votre espace SECA avec votre compte verifie.', ar: 'ادخل الى مساحة SECA بحسابك الموثق.' },
  'Admin accounts are provisioned only by the local admin script.': { fr: "Les comptes admin sont crees uniquement par le script d'administration local.", ar: 'يتم انشاء حسابات المسؤول فقط عبر سكربت الادمن المحلي.' },
  'Website Access Control': { fr: "Controle d'acces aux sites web", ar: 'التحكم في الوصول للمواقع' },
  'Manage blocked domains for all devices using your proxy.': { fr: 'Gerez les domaines bloques pour tous les appareils utilisant votre proxy.', ar: 'ادِر النطاقات المحجوبة لكل الاجهزة التي تستخدم البروكسي.' },
  Refresh: { fr: 'Actualiser', ar: 'تحديث' },
  'Add domain or URL': { fr: 'Ajouter un domaine ou une URL', ar: 'اضافة نطاق او رابط' },
  'example.com or https://example.com/page': { fr: 'example.com ou https://example.com/page', ar: 'example.com او https://example.com/page' },
  'Add Block': { fr: 'Ajouter un blocage', ar: 'اضافة حظر' },
  'Input is normalized to wildcard format (example: *.domain.com).': { fr: 'La saisie est normalisee au format wildcard (exemple : *.domain.com).', ar: 'يتم تحويل الادخال الى صيغة wildcard مثل: *.domain.com.' },
  'Active Block Rules': { fr: 'Regles de blocage actives', ar: 'قواعد الحظر النشطة' },
  'Loading rules...': { fr: 'Chargement des regles...', ar: 'جار تحميل القواعد...' },
  'No blocked domains configured yet.': { fr: 'Aucun domaine bloque configure pour le moment.', ar: 'لا توجد نطاقات محجوبة حتى الان.' },
  'No note': { fr: 'Aucune note', ar: 'لا توجد ملاحظة' },
  Enabled: { fr: 'Active', ar: 'مفعل' },
  Disabled: { fr: 'Desactive', ar: 'معطل' },
  Remove: { fr: 'Supprimer', ar: 'ازالة' },
  'Check file hashes against malware databases': { fr: 'Verifier les hashes des fichiers contre les bases de malwares', ar: 'تحقق من بصمات الملفات مقابل قواعد بيانات البرمجيات الخبيثة' },
  'Check Hash': { fr: 'Verifier le hash', ar: 'فحص البصمة' },
  'Checking Hash...': { fr: 'Verification du hash...', ar: 'جار فحص البصمة...' },
  'Searching malware databases and threat feeds': { fr: 'Recherche dans les bases de malwares et flux de menaces', ar: 'البحث في قواعد بيانات البرمجيات الخبيثة ومصادر التهديد' },
  'Scan Complete': { fr: 'Analyse terminee', ar: 'اكتمل الفحص' },
  'Hash Value': { fr: 'Valeur du hash', ar: 'قيمة البصمة' },
  'Hash Type': { fr: 'Type de hash', ar: 'نوع البصمة' },
  'Found in Database': { fr: 'Trouve dans la base', ar: 'موجود في قاعدة البيانات' },
  'Detections / Engines': { fr: 'Detections / Moteurs', ar: 'الكشوفات / المحركات' },
  'Threat Score': { fr: 'Score de menace', ar: 'درجة التهديد' },
  'Malware Detected': { fr: 'Malware detecte', ar: 'تم اكتشاف برمجية خبيثة' },
  'Malware Family': { fr: 'Famille de malware', ar: 'عائلة البرمجية الخبيثة' },
  'First Seen': { fr: 'Premiere apparition', ar: 'اول ظهور' },
  'Suspicious Indicators': { fr: 'Indicateurs suspects', ar: 'مؤشرات مشبوهة' },
  'No Threats Found': { fr: 'Aucune menace detectee', ar: 'لم يتم العثور على تهديدات' },
  'This hash has suspicious characteristics but no confirmed malware. Further analysis recommended.': { fr: 'Ce hash presente des caracteristiques suspectes sans malware confirme. Une analyse complementaire est recommandee.', ar: 'هذه البصمة تحتوي على خصائص مشبوهة بدون تأكيد لبرمجية خبيثة. يوصى بتحليل اضافي.' },
  'This hash was not found in any known malware databases. The file appears to be clean.': { fr: 'Ce hash n a ete trouve dans aucune base de malwares connue. Le fichier semble propre.', ar: 'لم يتم العثور على هذه البصمة في اي قاعدة بيانات معروفة. يبدو الملف سليما.' },
  'Advanced URL Scanner': { fr: "Analyseur d'URL avance", ar: 'فاحص الروابط المتقدم' },
  'Email Threat Scanner': { fr: "Analyseur de menaces email", ar: 'فاحص تهديدات البريد' },
  '4-layer security analysis for comprehensive threat detection': { fr: 'Analyse de securite en 4 couches pour une detection complete des menaces', ar: 'تحليل امني من 4 طبقات لاكتشاف شامل للتهديدات' },
  'Analyze .eml email files for phishing, spoofing, malicious URLs, and risky attachments': { fr: 'Analysez les fichiers email .eml pour le phishing, le spoofing, les URL malveillantes et les pieces jointes a risque', ar: 'حلل ملفات البريد .eml لاكتشاف التصيد والانتحال والروابط الخبيثة والمرفقات الخطرة' },
  'URL Analysis Layers': { fr: "Couches d'analyse URL", ar: 'طبقات تحليل الروابط' },
  'Did You Know?': { fr: 'Le saviez-vous ?', ar: 'هل تعلم؟' },
  'Security fact: every URL is checked through four independent risk layers.': { fr: 'Info securite : chaque URL est verifiee par quatre couches de risque independantes.', ar: 'معلومة امنية: يتم فحص كل رابط عبر اربع طبقات مستقلة من المخاطر.' },
  'Security fact: URL format anomalies are often the fastest phishing clue.': { fr: "Info securite : les anomalies de format URL sont souvent l'indice de phishing le plus rapide.", ar: 'معلومة امنية: غالبا ما تكون شذوذات صيغة الرابط اسرع مؤشر على التصيد.' },
  'Security fact: Reputation and content signals together reduce false positives.': { fr: "Info securite : combiner reputation et contenu reduit les faux positifs.", ar: 'معلومة امنية: الجمع بين اشارات السمعة والمحتوى يقلل النتائج الايجابية الكاذبة.' },
  'Security fact: Layered analysis catches threats single checks miss.': { fr: "Info securite : l'analyse multicouche detecte des menaces que les verifications uniques ratent.", ar: 'معلومة امنية: يكشف التحليل متعدد الطبقات تهديدات تفوتها الفحوصات المنفردة.' },
  'This URL matched a known threat feed indicator.': { fr: 'Cette URL correspond a un indicateur connu dans le flux de menaces.', ar: 'هذا الرابط طابق مؤشرا معروفا في مصدر التهديد.' },
  'Malicious URLs': { fr: 'URL malveillantes', ar: 'روابط خبيثة' },
  'Verified URLs': { fr: 'URL verifiees', ar: 'روابط موثقة' },
  'Malicious Domains': { fr: 'Domaines malveillants', ar: 'نطاقات خبيثة' },
  'Platform Scans': { fr: 'Scans plateforme', ar: 'فحوصات المنصة' },
  'Malicious Verdicts': { fr: 'Verdicts malveillants', ar: 'احكام خبيثة' },
  'Search URL': { fr: "Analyser l'URL", ar: 'فحص الرابط' },
  'Format Validation': { fr: 'Validation du format', ar: 'التحقق من الصيغة' },
  'Threat Feed Lookup': { fr: 'Recherche dans les flux de menaces', ar: 'البحث في مصادر التهديد' },
  'Domain Reputation': { fr: 'Reputation du domaine', ar: 'سمعة النطاق' },
  'Content Analysis': { fr: 'Analyse du contenu', ar: 'تحليل المحتوى' },
  'Protocol, syntax, suspicious patterns': { fr: 'Protocole, syntaxe, motifs suspects', ar: 'البروتوكول والصياغة والانماط المشبوهة' },
  'Known malicious URL/domain match': { fr: 'Correspondance avec URL/domaine malveillant connu', ar: 'مطابقة مع رابط او نطاق خبيث معروف' },
  'Trust score and domain risk checks': { fr: 'Score de confiance et controles de risque du domaine', ar: 'درجة الثقة وفحوصات مخاطر النطاق' },
  'Indicators and behavior scoring': { fr: 'Indicateurs et score de comportement', ar: 'المؤشرات وتقييم السلوك' },
  'Overall Threat Score': { fr: 'Score global de menace', ar: 'الدرجة العامة للتهديد' },
  'Verdict Breakdown': { fr: 'Repartition du verdict', ar: 'تفصيل الحكم' },
  'Scan Comparison': { fr: 'Comparaison des scans', ar: 'مقارنة الفحوصات' },
  'Previous score': { fr: 'Score precedent', ar: 'النتيجة السابقة' },
  Delta: { fr: 'Ecart', ar: 'الفرق' },
  'Overview of your security scans': { fr: 'Vue d ensemble de vos analyses de securite', ar: 'نظرة عامة على فحوصاتك الامنية' },
  'Auto-refresh every 10s': { fr: 'Actualisation automatique toutes les 10s', ar: 'تحديث تلقائي كل 10 ثوان' },
  'Last update:': { fr: 'Derniere mise a jour :', ar: 'اخر تحديث:' },
  'Waiting...': { fr: 'En attente...', ar: 'في الانتظار...' },
  'Recent Scans': { fr: 'Analyses recentes', ar: 'احدث الفحوصات' },
  'Open report': { fr: 'Ouvrir le rapport', ar: 'فتح التقرير' },
  'Loading scans...': { fr: 'Chargement des analyses...', ar: 'جار تحميل الفحوصات...' },
  'No scans yet': { fr: 'Aucune analyse pour le moment', ar: 'لا توجد فحوصات بعد' },
  'Total Scans': { fr: 'Total des analyses', ar: 'اجمالي الفحوصات' },
  'Scan Report': { fr: 'Rapport de scan', ar: 'تقرير الفحص' },
  'Detailed report for scan': { fr: 'Rapport detaille pour le scan', ar: 'تقرير مفصل للفحص' },
  'Loading full scan report...': { fr: 'Chargement du rapport complet...', ar: 'جار تحميل التقرير الكامل...' },
  'URL Scanning': { fr: "Analyse d'URL", ar: 'فحص الروابط' },
  'Email Scanning': { fr: 'Analyse email', ar: 'فحص البريد الالكتروني' },
  'File Scanning': { fr: 'Analyse de fichiers', ar: 'فحص الملفات' },
  'Hash Checking': { fr: 'Verification de hash', ar: 'فحص البصمة' },
  'Gateway Monitoring': { fr: 'Surveillance de la passerelle', ar: 'مراقبة البوابة' },
  'Security Scan': { fr: 'Analyse de securite', ar: 'فحص امني' },
  'Threat feed match': { fr: 'Correspondance flux de menaces', ar: 'تطابق مع مصدر تهديدات' },
  'Reputation score': { fr: 'Score de reputation', ar: 'درجة السمعة' },
  'Content indicators': { fr: 'Indicateurs de contenu', ar: 'مؤشرات المحتوى' },
  'URLs extracted': { fr: 'URL extraites', ar: 'الروابط المستخرجة' },
  Attachments: { fr: 'Pieces jointes', ar: 'المرفقات' },
  'Auth failures': { fr: "Echecs d'authentification", ar: 'فشل التحقق' },
  'Phishing signals': { fr: 'Signaux de phishing', ar: 'اشارات التصيد' },
  Subject: { fr: 'Sujet', ar: 'الموضوع' },
  Sender: { fr: 'Expediteur', ar: 'المرسل' },
  'Hash type': { fr: 'Type de hash', ar: 'نوع البصمة' },
  Detections: { fr: 'Detections', ar: 'الاكتشافات' },
  'Database match': { fr: 'Correspondance base de donnees', ar: 'تطابق قاعدة البيانات' },
  'Malware family': { fr: 'Famille malveillante', ar: 'عائلة البرمجية الخبيثة' },
  'File category': { fr: 'Categorie de fichier', ar: 'فئة الملف' },
  'File size': { fr: 'Taille du fichier', ar: 'حجم الملف' },
  Entropy: { fr: 'Entropie', ar: 'الاعتلاج' },
  'Threat indicators': { fr: 'Indicateurs de menace', ar: 'مؤشرات التهديد' },
  'Code alerts': { fr: 'Alertes de code', ar: 'تنبيهات الكود' },
  'No structured detail payload available for this scan.': { fr: 'Aucune charge detaillee structuree pour ce scan.', ar: 'لا توجد بيانات تفصيلية منظمة لهذا الفحص.' },
  'Email Threat Analysis': { fr: 'Analyse des menaces email', ar: 'تحليل تهديدات البريد' },
  'Header Checks': { fr: 'Verifications des en-tetes', ar: 'فحوصات الترويسة' },
  'Sender Identity': { fr: "Identite de l'expediteur", ar: 'هوية المرسل' },
  'From, Reply-To, mailed-by, signed-by, auth results': { fr: 'From, Reply-To, mailed-by, signed-by, resultats auth', ar: 'من وReply-To وmailed-by وsigned-by ونتائج التحقق' },
  'URL Reuse': { fr: 'Reutilisation des URL', ar: 'اعادة استخدام الروابط' },
  'Link Extraction': { fr: 'Extraction des liens', ar: 'استخراج الروابط' },
  'Every extracted link is re-scored by the URL engine': { fr: "Chaque lien extrait est re-evalue par le moteur d'URL", ar: 'كل رابط مستخرج يعاد تقييمه بواسطة محرك الروابط' },
  'Attachment Reuse': { fr: 'Reutilisation des pieces jointes', ar: 'اعادة استخدام المرفقات' },
  'File Analysis': { fr: 'Analyse de fichier', ar: 'تحليل الملفات' },
  'Attachments inherit the static file analysis pipeline': { fr: "Les pieces jointes reutilisent la chaine d'analyse statique des fichiers", ar: 'المرفقات ترث مسار التحليل الثابت للملفات' },
  'What This Catches': { fr: 'Ce que cela detecte', ar: 'ما الذي يكتشفه هذا' },
  '- Sender spoofing and Reply-To mismatch': { fr: "- Usurpation d'expediteur et incoherence Reply-To", ar: '- انتحال المرسل وعدم تطابق Reply-To' },
  '- Credential theft and urgency wording': { fr: '- Vol de credentials et formulations urgentes', ar: '- سرقة بيانات الاعتماد وصياغات الاستعجال' },
  '- Malicious or suspicious extracted URLs': { fr: '- URL extraites malveillantes ou suspectes', ar: '- روابط مستخرجة خبيثة او مشبوهة' },
  '- Risky attachments such as scripts, archives, or executables': { fr: '- Pieces jointes a risque comme scripts, archives ou executables', ar: '- مرفقات خطرة مثل السكربتات والارشيفات والملفات التنفيذية' },
  'Upload .eml Email': { fr: 'Importer un email .eml', ar: 'رفع بريد .eml' },
  'The scanner now accepts email files only. This preserves headers, MIME structure, body formatting, and attachments.': { fr: "Le scanner accepte maintenant uniquement les fichiers email. Cela preserve les en-tetes, la structure MIME, la mise en forme et les pieces jointes.", ar: 'الماسح يقبل الان ملفات البريد فقط. هذا يحافظ على الترويسات وبنية MIME وتنسيق المحتوى والمرفقات.' },
  'Scanning Email...': { fr: "Analyse de l'email...", ar: 'جار فحص البريد...' },
  'Scan Email': { fr: "Analyser l'email", ar: 'فحص البريد' },
  'Email Scan Complete': { fr: "Analyse de l'email terminee", ar: 'اكتمل فحص البريد' },
  'Main audit view (devices moved to dedicated page).': { fr: "Vue d'audit principale (les appareils ont ete deplaces vers une page dediee).", ar: 'واجهة التدقيق الرئيسية (تم نقل الاجهزة الى صفحة مخصصة).' },
  'Proxy Status': { fr: 'Etat du proxy', ar: 'حالة البروكسي' },
  Running: { fr: 'En cours', ar: 'قيد التشغيل' },
  Stopped: { fr: 'Arrete', ar: 'متوقف' },
  'No data': { fr: 'Aucune donnee', ar: 'لا توجد بيانات' },
  'Connected Devices': { fr: 'Appareils connectes', ar: 'الاجهزة المتصلة' },
  'Click to open devices page': { fr: 'Cliquez pour ouvrir la page des appareils', ar: 'اضغط لفتح صفحة الاجهزة' },
  'Block Rate': { fr: 'Taux de blocage', ar: 'معدل الحظر' },
  'Total Events': { fr: 'Total des evenements', ar: 'اجمالي الاحداث' },
  'All Actions': { fr: 'Toutes les actions', ar: 'كل الاجراءات' },
  'All Verdicts': { fr: 'Tous les verdicts', ar: 'كل الاحكام' },
  Blocked: { fr: 'Bloque', ar: 'محظور' },
  Allowed: { fr: 'Autorise', ar: 'مسموح' },
  'Search action, details, user, timestamp': { fr: 'Rechercher action, details, utilisateur, horodatage', ar: 'ابحث في الاجراء والتفاصيل والمستخدم والوقت' },
  Clear: { fr: 'Effacer', ar: 'مسح' },
  'Loading logs...': { fr: 'Chargement des journaux...', ar: 'جار تحميل السجلات...' },
  Timestamp: { fr: 'Horodatage', ar: 'الوقت' },
  Action: { fr: 'Action', ar: 'الاجراء' },
  Details: { fr: 'Details', ar: 'التفاصيل' },
  Devices: { fr: 'Appareils', ar: 'الاجهزة' },
  'Click a device to show its logs.': { fr: 'Cliquez sur un appareil pour afficher ses journaux.', ar: 'اضغط على جهاز لعرض سجلاته.' },
  'Export Device Logs': { fr: "Exporter les journaux de l'appareil", ar: 'تصدير سجلات الجهاز' },
  Connected: { fr: 'Connecte', ar: 'متصل' },
  Disconnected: { fr: 'Deconnecte', ar: 'غير متصل' },
  'Activity online': { fr: 'Activite en ligne', ar: 'النشاط متصل' },
  'Select a device.': { fr: 'Selectionnez un appareil.', ar: 'اختر جهازا.' },
  'Search action/details': { fr: 'Rechercher action/details', ar: 'ابحث في الاجراءات/التفاصيل' },
  System: { fr: 'Systeme', ar: 'النظام' },
  'Design preview for employee web-usage gateway monitoring and policy control.': { fr: "Apercu de design pour la surveillance d'usage web des employes et le controle des politiques.", ar: 'معاينة تصميم لمراقبة استخدام الويب للموظفين والتحكم في السياسات.' },
  'UI Mock + Real Scan Flavor': { fr: 'Maquette UI + touche scan reel', ar: 'واجهة تجريبية + طابع فحص واقعي' },
  Overview: { fr: "Vue d'ensemble", ar: 'نظرة عامة' },
  Employees: { fr: 'Employes', ar: 'الموظفون' },
  Policies: { fr: 'Politiques', ar: 'السياسات' },
  'Website activity': { fr: 'Activite web', ar: 'نشاط المواقع' },
  'Advanced File Scanner': { fr: 'Analyseur de fichiers avance', ar: 'فاحص الملفات المتقدم' },
  'Upload a file for layered static and dynamic analysis': { fr: 'Telechargez un fichier pour une analyse statique et dynamique en couches', ar: 'ارفع ملفا لتحليل ثابت وديناميكي متعدد الطبقات' },
  'Upload File': { fr: 'Televerser un fichier', ar: 'رفع ملف' },
  'Security fact: static and dynamic analysis complement each other.': { fr: "Info securite : les analyses statique et dynamique se completent.", ar: 'معلومة امنية: التحليل الثابت والديناميكي يكمل كل منهما الاخر.' },
  'Security fact: entropy spikes can reveal packed or obfuscated binaries.': { fr: 'Info securite : des pics d entropie peuvent reveler des binaires compactes ou obfusquees.', ar: 'معلومة امنية: قد تكشف قمم الانتروبيا ملفات ثنائية مضغوطة او مموهة.' },
  'Security fact: dynamic behavior often exposes threats static checks miss.': { fr: 'Info securite : le comportement dynamique revele souvent des menaces ratees par le statique.', ar: 'معلومة امنية: غالبا ما يكشف السلوك الديناميكي تهديدات تفوتها الفحوصات الثابتة.' },
  'Security fact: combining hashes and behavior reduces false positives.': { fr: 'Info securite : combiner les hashes et le comportement reduit les faux positifs.', ar: 'معلومة امنية: دمج البصمات مع السلوك يقلل النتائج الايجابية الكاذبة.' },
  'File Analysis Layers': { fr: "Couches d'analyse fichier", ar: 'طبقات تحليل الملفات' },
  '4-layer static analysis + Windows Sandbox dynamic execution': { fr: 'Analyse statique 4 couches + execution dynamique Windows Sandbox', ar: 'تحليل ثابت من 4 طبقات + تنفيذ ديناميكي عبر Windows Sandbox' },
  'Layer 1': { fr: 'Couche 1', ar: 'الطبقة 1' },
  'Layer 2': { fr: 'Couche 2', ar: 'الطبقة 2' },
  'Layer 3': { fr: 'Couche 3', ar: 'الطبقة 3' },
  'Layer 4': { fr: 'Couche 4', ar: 'الطبقة 4' },
  'Layer 5': { fr: 'Couche 5', ar: 'الطبقة 5' },
  'File Information': { fr: 'Informations fichier', ar: 'معلومات الملف' },
  'Metadata, type classification and entropy': { fr: 'Metadonnees, classification du type et entropie', ar: 'البيانات الوصفية وتصنيف النوع والاعتلاج' },
  'Cryptographic hashes and known-bad database lookup': { fr: 'Hashes cryptographiques et recherche dans une base malveillante connue', ar: 'بصمات تشفيرية والبحث في قاعدة بيانات خبيثة معروفة' },
  'Signature and heuristic threat identification': { fr: 'Identification des menaces par signatures et heuristiques', ar: 'تحديد التهديدات عبر التواقيع والاستدلالات' },
  'Code Analysis': { fr: 'Analyse du code', ar: 'تحليل الكود' },
  'Suspicious patterns, packer detection and imports': { fr: 'Motifs suspects, detection de packer et imports', ar: 'انماط مشبوهة واكتشاف الضغط والاستيرادات' },
  'Drop your file here or click to browse': { fr: 'Deposez votre fichier ici ou cliquez pour parcourir', ar: 'اسحب ملفك هنا او اضغط للتصفح' },
  'All file types supported • Max 100 MB': { fr: 'Tous les types de fichiers sont pris en charge • 100 Mo max', ar: 'كل انواع الملفات مدعومة • الحد الاقصى 100 م.ب' },
  'Run another static scan to unlock trend comparison.': { fr: 'Lancez une autre analyse statique pour debloquer la comparaison.', ar: 'قم بتشغيل فحص ثابت اخر لفتح المقارنة.' },
  'File Name': { fr: 'Nom du fichier', ar: 'اسم الملف' },
  Size: { fr: 'Taille', ar: 'الحجم' },
  Extension: { fr: 'Extension', ar: 'الامتداد' },
  'Risk Category': { fr: 'Categorie de risque', ar: 'فئة المخاطر' },
  'High - may be packed/encrypted': { fr: 'Elevee - peut etre compacte/chiffree', ar: 'مرتفع - قد يكون مضغوطا او مشفرا' },
  'Hash found in malware database': { fr: 'Hash trouve dans la base malveillante', ar: 'تم العثور على البصمة في قاعدة البيانات الخبيثة' },
  'Not found in malware database': { fr: 'Aucune correspondance dans la base malveillante', ar: 'لم يتم العثور عليها في قاعدة البيانات الخبيثة' },
  'Malware Family:': { fr: 'Famille malveillante :', ar: 'عائلة البرمجية الخبيثة:' },
  'No threats detected': { fr: 'Aucune menace detectee', ar: 'لم يتم اكتشاف اي تهديد' },
  'Code appears obfuscated': { fr: 'Le code semble obfusque', ar: 'يبدو الكود مموها' },
  'Imported DLLs': { fr: 'DLL importees', ar: 'مكتبات DLL المستوردة' },
  'Structural Anomalies': { fr: 'Anomalies structurelles', ar: 'شذوذات هيكلية' },
  'No suspicious code patterns': { fr: 'Aucun motif de code suspect', ar: 'لا توجد انماط كود مشبوهة' },
  'Code analysis N/A for': { fr: "Analyse du code non applicable pour", ar: 'تحليل الكود غير متاح لملفات' },
  'Threat detection N/A for': { fr: 'Detection de menace non applicable pour', ar: 'كشف التهديد غير متاح لملفات' },
  files: { fr: 'fichiers', ar: 'ملفات' },
  executable: { fr: 'executable', ar: 'تنفيذي' },
  script: { fr: 'script', ar: 'سكريبت' },
  archive: { fr: 'archive', ar: 'ارشيف' },
  document: { fr: 'document', ar: 'مستند' },
  media: { fr: 'media', ar: 'وسائط' },
  unknown: { fr: 'inconnu', ar: 'غير معروف' },
  'Static Scan Complete': { fr: 'Analyse statique terminee', ar: 'اكتمل الفحص الثابت' },
  'Static Score Breakdown': { fr: 'Detail du score statique', ar: 'تفصيل الدرجة الثابتة' },
  'Static Comparison': { fr: 'Comparaison statique', ar: 'المقارنة الثابتة' },
  'Run one more scan to unlock comparison insights.': { fr: 'Lancez une autre analyse pour debloquer la comparaison.', ar: 'قم بتشغيل فحص اخر لفتح معلومات المقارنة.' },
  'Running Layer': { fr: 'Execution de la couche', ar: 'تشغيل الطبقة' },
  'Score contribution': { fr: 'Contribution au score', ar: 'المساهمة في الدرجة' },
  'Hash Database': { fr: 'Base de hashes', ar: 'قاعدة بيانات البصمات' },
  'Entropy Risk': { fr: "Risque d'entropie", ar: 'خطر الاعتلاج' },
  'Threat Signatures': { fr: 'Signatures de menace', ar: 'تواقيع التهديد' },
  'Code Indicators': { fr: 'Indicateurs de code', ar: 'مؤشرات الكود' },
  Format: { fr: 'Format', ar: 'الصيغة' },
  'Threat Feed': { fr: 'Flux de menaces', ar: 'مصدر التهديد' },
  Reputation: { fr: 'Reputation', ar: 'السمعة' },
  Content: { fr: 'Contenu', ar: 'المحتوى' },
  'Suspicious Strings': { fr: 'Chaines suspectes', ar: 'سلاسل مشبوهة' },
  Packer: { fr: 'Compresseur', ar: 'الضاغط' },
  Cancel: { fr: 'Annuler', ar: 'الغاء' },
  'Cancelling...': { fr: 'Annulation...', ar: 'جار الالغاء...' },
  Normal: { fr: 'Normal', ar: 'طبيعي' },
  normal: { fr: 'normal', ar: 'طبيعي' },
  Monitored: { fr: 'Surveille', ar: 'مراقب' },
  Mode: { fr: 'Mode', ar: 'الوضع' },
  ACTIVE: { fr: 'ACTIF', ar: 'نشط' },
  DISABLED: { fr: 'DESACTIVE', ar: 'معطل' },
  RISK: { fr: 'RISQUE', ar: 'خطورة' },
  HIGH: { fr: 'ELEVE', ar: 'مرتفع' },
  MEDIUM: { fr: 'MOYEN', ar: 'متوسط' },
  LOW: { fr: 'FAIBLE', ar: 'منخفض' },
  'Dynamic Sandbox Analysis': { fr: 'Analyse dynamique Sandbox', ar: 'تحليل ديناميكي داخل Sandbox' },
  'Run Dynamic Sandbox Analysis': { fr: "Lancer l'analyse dynamique Sandbox", ar: 'تشغيل التحليل الديناميكي داخل Sandbox' },
  'Process monitoring': { fr: 'Surveillance des processus', ar: 'مراقبة العمليات' },
  'Network traffic': { fr: 'Trafic reseau', ar: 'حركة الشبكة' },
  'File system': { fr: 'Systeme de fichiers', ar: 'نظام الملفات' },
  Registry: { fr: 'Registre', ar: 'السجل' },
  'Run Dynamic URL Scan': { fr: "Lancer l'analyse URL dynamique", ar: 'تشغيل فحص الرابط الديناميكي' },
  'Layer 5: Dynamic URL Analysis (Sandbox)': { fr: "Couche 5 : analyse URL dynamique (Sandbox)", ar: 'الطبقة 5: تحليل الروابط الديناميكي (Sandbox)' },
  'Runs only for static clean/suspicious URLs. Local/private targets are blocked.': { fr: 'Fonctionne seulement pour les URL statiques propres/suspectes. Les cibles locales/privees sont bloquees.', ar: 'يعمل فقط مع الروابط النظيفة او المشبوهة في الفحص الثابت. يتم حظر الاهداف المحلية والخاصة.' },
  'Policy block active: this URL is statically malicious, so sandbox launch is refused.': { fr: "Blocage politique actif : cette URL est statiquement malveillante, le sandbox est refuse.", ar: 'سياسة الحظر مفعلة: هذا الرابط خبيث في الفحص الثابت لذلك تم رفض تشغيل الـ sandbox.' },
  'Running sandbox URL analysis...': { fr: "Execution de l'analyse URL dans le sandbox...", ar: 'جار تشغيل تحليل الرابط داخل الـ sandbox...' },
  Verdict: { fr: 'Verdict', ar: 'الحكم' },
  'Dynamic Threat Score': { fr: 'Score de menace dynamique', ar: 'درجة التهديد الديناميكي' },
  Duration: { fr: 'Duree', ar: 'المدة' },
  'Observed Connections': { fr: 'Connexions observees', ar: 'الاتصالات المرصودة' },
  'Dynamic Summary': { fr: 'Resume dynamique', ar: 'ملخص ديناميكي' },
  'Top Processes': { fr: 'ابرز العمليات', ar: 'اهم العمليات' },
  'No notable process activity.': { fr: 'Aucune activite processus notable.', ar: 'لا توجد نشاطات عمليات ملحوظة.' },
  'Top Network Connections': { fr: 'ابرز الاتصالات الشبكية', ar: 'اهم اتصالات الشبكة' },
  'No external network telemetry captured.': { fr: 'Aucune telemetrie reseau externe capturee.', ar: 'لم يتم التقاط قياسات شبكة خارجية.' },
  'URL structure and syntax analysis': { fr: 'Analyse de la structure et de la syntaxe URL', ar: 'تحليل بنية الرابط وصيغته' },
  'Issues Detected:': { fr: 'Problemes detectes :', ar: 'المشاكل المكتشفة:' },
  'No format issues detected': { fr: 'Aucun probleme de format detecte', ar: 'لم يتم اكتشاف مشاكل في الصيغة' },
  'Threat Feed Database': { fr: 'Base de flux de menaces', ar: 'قاعدة بيانات مصادر التهديد' },
  'Known malicious URL and domain lookup': { fr: "Recherche d'URL et domaines malveillants connus", ar: 'البحث عن روابط ونطاقات خبيثة معروفة' },
  'Not Found in Database': { fr: 'Non trouve dans la base', ar: 'لم يتم العثور عليه في قاعدة البيانات' },
  Source: { fr: 'Source', ar: 'المصدر' },
  'No additional info': { fr: 'Aucune information supplementaire', ar: 'لا توجد معلومات اضافية' },
  'Domain matches:': { fr: 'Correspondances domaine :', ar: 'تطابقات النطاق:' },
  'No Layer 2 data returned.': { fr: 'Aucune donnee retournee pour la couche 2.', ar: 'لم يتم ارجاع بيانات للطبقة 2.' },
  'Domain trust and reputation analysis': { fr: 'Analyse de confiance et de reputation du domaine', ar: 'تحليل ثقة وسمعة النطاق' },
  'Reputation Score': { fr: 'Score de reputation', ar: 'درجة السمعة' },
  'Reputation Issues:': { fr: 'Problemes de reputation :', ar: 'مشاكل السمعة:' },
  'No reputation issues detected': { fr: 'Aucun probleme de reputation detecte', ar: 'لم يتم اكتشاف مشاكل سمعة' },
  'No Layer 3 data returned.': { fr: 'Aucune donnee retournee pour la couche 3.', ar: 'لم يتم ارجاع بيانات للطبقة 3.' },
  'Behavioral and content indicators': { fr: 'Indicateurs comportementaux et de contenu', ar: 'مؤشرات سلوكية ومؤشرات محتوى' },
  'Indicators Found:': { fr: 'Indicateurs trouves :', ar: 'المؤشرات الموجودة:' },
  'No suspicious content indicators': { fr: 'Aucun indicateur de contenu suspect', ar: 'لا توجد مؤشرات محتوى مشبوهة' },
  'Content threat score': { fr: 'Score de menace du contenu', ar: 'درجة تهديد المحتوى' },
  'No Layer 4 data returned.': { fr: 'Aucune donnee retournee pour la couche 4.', ar: 'لم يتم ارجاع بيانات للطبقة 4.' },
  'Active Gateways': { fr: 'Passerelles actives', ar: 'البوابات النشطة' },
  'Tracked Searches': { fr: 'Recherches suivies', ar: 'عمليات البحث المتتبعة' },
  'Policy Hits': { fr: 'Declenchements de politiques', ar: 'ضربات السياسات' },
  'High-Risk Users': { fr: 'Utilisateurs a haut risque', ar: 'مستخدمون عالي الخطورة' },
  'Employee Search Distribution': { fr: 'Repartition des recherches employees', ar: 'توزيع بحث الموظفين' },
  'Employee Behavior Breakdown': { fr: 'Repartition du comportement des employes', ar: 'تفصيل سلوك الموظفين' },
  'Policy Builder Preview': { fr: 'Apercu du constructeur de politiques', ar: 'معاينة منشئ السياسات' },
  'Top websites from URL scan data': { fr: "Principaux sites a partir des donnees d'analyse URL", ar: 'ابرز المواقع من بيانات فحص الروابط' },
  'tracked hits': { fr: 'hits suivis', ar: 'الزيارات المتتبعة' },
  searches: { fr: 'recherches', ar: 'عمليات بحث' },
  'Non-work trend:': { fr: 'Tendance hors travail :', ar: 'اتجاه غير مهني:' },
  'matches this week': { fr: 'correspondances cette semaine', ar: 'مطابقات هذا الاسبوع' },
  'Gateway Device Status': { fr: 'Etat des appareils de la passerelle', ar: 'حالة اجهزة البوابة' },
  'Real-time': { fr: 'Temps reel', ar: 'الوقت الحقيقي' },
  'Gateway Health Index': { fr: 'Indice de sante de la passerelle', ar: 'مؤشر صحة البوابة' },
  'endpoints operational': { fr: 'terminaux operationnels', ar: 'نقاط نهاية عاملة' },
  Online: { fr: 'En ligne', ar: 'متصل' },
  Warning: { fr: 'Alerte', ar: 'تحذير' },
  Offline: { fr: 'Hors ligne', ar: 'غير متصل' },
  'last sync': { fr: 'derniere synchro', ar: 'اخر مزامنة' },
  'Live Traffic Snapshot': { fr: 'Apercu du trafic en direct', ar: 'لقطة لحركة المرور المباشرة' },
  'recent events': { fr: 'evenements recents', ar: 'احداث حديثة' },
  'Choose file': { fr: 'Choisir un fichier', ar: 'اختر ملفا' },
  'Static Analysis': { fr: 'Analyse statique', ar: 'التحليل الثابت' },
  'Dynamic Analysis': { fr: 'Analyse dynamique', ar: 'التحليل الديناميكي' },
  'Analysis Report': { fr: "Rapport d'analyse", ar: 'تقرير التحليل' },
  'Session expired. Please sign in again.': { fr: 'Session expiree. Veuillez vous reconnecter.', ar: 'انتهت الجلسة. يرجى تسجيل الدخول مرة اخرى.' },
  'An error occurred': { fr: 'Une erreur est survenue', ar: 'حدث خطا' },
  'Failed to fetch logs': { fr: 'Impossible de recuperer les journaux', ar: 'فشل في جلب السجلات' },
  'Failed to fetch audit logs': { fr: "Impossible de recuperer les journaux d'audit", ar: 'فشل في جلب سجلات التدقيق' },
  'Failed to fetch gateway telemetry': { fr: 'Impossible de recuperer la telemetrie de la passerelle', ar: 'فشل في جلب قياسات البوابة' },
  'Failed to load blocklist': { fr: 'Impossible de charger la blocklist', ar: 'فشل في تحميل قائمة الحظر' },
  'Please enter a valid domain or URL': { fr: 'Veuillez saisir un domaine ou une URL valide', ar: 'يرجى ادخال نطاق او رابط صالح' },
  'Failed to add block rule': { fr: "Echec de l'ajout de la regle de blocage", ar: 'فشل في اضافة قاعدة الحظر' },
  'Failed to update rule': { fr: 'Echec de la mise a jour de la regle', ar: 'فشل في تحديث القاعدة' },
  'Failed to remove rule': { fr: 'Echec de la suppression de la regle', ar: 'فشل في حذف القاعدة' },
  'You must be signed in.': { fr: 'Vous devez etre connecte.', ar: 'يجب ان تكون مسجل الدخول.' },
  'Upload an .eml email file to continue.': { fr: 'Telechargez un fichier email .eml pour continuer.', ar: 'قم برفع ملف بريد .eml للمتابعة.' },
  'Email scan failed': { fr: "Echec de l'analyse email", ar: 'فشل فحص البريد' },
  'Please login and enter a valid URL': { fr: 'Veuillez vous connecter et saisir une URL valide', ar: 'يرجى تسجيل الدخول وادخال رابط صالح' },
  'Scan failed': { fr: "Echec de l'analyse", ar: 'فشل الفحص' },
  'Run static scan first, then start dynamic analysis.': { fr: "Lancez d'abord l'analyse statique puis l'analyse dynamique.", ar: 'قم بتشغيل التحليل الثابت اولا ثم ابدأ التحليل الديناميكي.' },
  'Dynamic URL analysis blocked by policy: static verdict is malicious.': { fr: "Analyse URL dynamique bloquee par la politique : le verdict statique est malveillant.", ar: 'تم حظر تحليل الرابط الديناميكي بسبب السياسة: الحكم الثابت خبيث.' },
  'Preparing URL sandbox environment...': { fr: "Preparation de l'environnement sandbox URL...", ar: 'جار تجهيز بيئة عزل الرابط...' },
  'Failed to start dynamic URL analysis.': { fr: "Impossible de demarrer l'analyse URL dynamique.", ar: 'فشل بدء تحليل الرابط الديناميكي.' },
  'Dynamic URL analysis failed.': { fr: "L'analyse URL dynamique a echoue.", ar: 'فشل تحليل الرابط الديناميكي.' },
};

type RegexTranslator = {
  pattern: RegExp;
  render: (match: RegExpExecArray, language: Exclude<Language, 'en'>) => string;
};

const regexTranslations: RegexTranslator[] = [
  {
    pattern: /^Code expires in (\d+) minutes and can be re-sent after (\d+)s\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `Le code expire dans ${match[1]} minutes et peut etre renvoye apres ${match[2]}s.`
        : `تنتهي صلاحية الرمز خلال ${match[1]} دقيقة ويمكن اعادة ارساله بعد ${match[2]}ث.`,
  },
  {
    pattern: /^Code expires in (\d+) minutes\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `Le code expire dans ${match[1]} minutes.`
        : `تنتهي صلاحية الرمز خلال ${match[1]} دقيقة.`,
  },
  {
    pattern: /^Dev OTP: (\d+)$/,
    render: (match, language) =>
      language === 'fr'
        ? `OTP dev : ${match[1]}`
        : `رمز التطوير: ${match[1]}`,
  },
  {
    pattern: /^Offline > (\d+)s$/,
    render: (match, language) =>
      language === 'fr'
        ? `Hors ligne > ${match[1]}s`
        : `غير متصل > ${match[1]}ث`,
  },
  {
    pattern: /^Active <= (\d+)s$/,
    render: (match, language) =>
      language === 'fr'
        ? `Actif <= ${match[1]}s`
        : `نشط <= ${match[1]}ث`,
  },
  {
    pattern: /^Offline after (\d+)s idle$/,
    render: (match, language) =>
      language === 'fr'
        ? `Hors ligne apres ${match[1]}s d'inactivite`
        : `غير متصل بعد ${match[1]}ث من الخمول`,
  },
  {
    pattern: /^Last activity: (.+) ago$/,
    render: (match, language) =>
      language === 'fr'
        ? `Derniere activite : il y a ${match[1]}`
        : `اخر نشاط: منذ ${match[1]}`,
  },
  {
    pattern: /^Last seen: (.+)$/,
    render: (match, language) =>
      language === 'fr'
        ? `Derniere apparition : ${match[1]}`
        : `اخر ظهور: ${match[1]}`,
  },
  {
    pattern: /^User #(\d+)$/,
    render: (match, language) =>
      language === 'fr'
        ? `Utilisateur #${match[1]}`
        : `المستخدم #${match[1]}`,
  },
  {
    pattern: /^Invalid (MD5|SHA1|SHA256) hash format\. Expected (\d+) hexadecimal characters\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `Format de hash ${match[1]} invalide. ${match[2]} caracteres hexadecimaux attendus.`
        : `تنسيق بصمة ${match[1]} غير صالح. المتوقع ${match[2]} محرفا سداسيا عشريا.`,
  },
  {
    pattern: /^(\d+) out of (\d+) engines flagged this file\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `${match[1]} moteurs sur ${match[2]} ont signale ce fichier.`
        : `تم وضع علامة على هذا الملف بواسطة ${match[1]} من اصل ${match[2]} محركات.`,
  },
  {
    pattern: /^Threat feed currently tracks ([\d.,\s]+) malicious URLs\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `Le flux de menaces suit actuellement ${match[1]} URL malveillantes.`
        : `يتتبع مصدر التهديد حاليا ${match[1]} رابطا خبيثا.`,
  },
  {
    pattern: /^([\d.,\s]+) unique malicious domains are indexed in your feed\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `${match[1]} domaines malveillants uniques sont indexes dans votre flux.`
        : `يوجد ${match[1]} نطاقا خبيثا فريدا مفهرسا في مصدر التهديد لديك.`,
  },
  {
    pattern: /^([\d.,\s]+) URL\/file scans are logged in your platform\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `${match[1]} scans URL/fichier sont journalises sur votre plateforme.`
        : `تم تسجيل ${match[1]} من فحوصات الروابط/الملفات في منصتك.`,
  },
  {
    pattern: /^([\d.,\s]+) historical scans were marked malicious\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `${match[1]} scans historiques ont ete marques malveillants.`
        : `تم تمييز ${match[1]} من الفحوصات السابقة على انها خبيثة.`,
  },
  {
    pattern: /^([\d.,\s]+) historical scans were marked suspicious\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `${match[1]} scans historiques ont ete marques suspects.`
        : `تم تمييز ${match[1]} من الفحوصات السابقة على انها مشبوهة.`,
  },
  {
    pattern: /^([\d.,\s]+) total security scans are logged in your platform\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `${match[1]} scans de securite au total sont journalises sur votre plateforme.`
        : `تم تسجيل ${match[1]} من فحوصات الامن الاجمالية في منصتك.`,
  },
  {
    pattern: /^([\d.,\s]+) historical scans were flagged malicious\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `${match[1]} scans historiques ont ete signales malveillants.`
        : `تم الابلاغ عن ${match[1]} من الفحوصات السابقة كخبيثة.`,
  },
  {
    pattern: /^([\d.,\s]+) scans were marked suspicious and need triage\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `${match[1]} scans ont ete marques suspects et necessitent un triage.`
        : `تم تمييز ${match[1]} من الفحوصات على انها مشبوهة وتحتاج الى فرز.`,
  },
  {
    pattern: /^Latest URL risk score: (\d+)\/100\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `Dernier score de risque URL : ${match[1]}/100.`
        : `اخر درجة مخاطرة للرابط: ${match[1]}/100.`,
  },
  {
    pattern: /^Latest static score: (\d+)\/100\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `Dernier score statique : ${match[1]}/100.`
        : `اخر درجة ثابتة: ${match[1]}/100.`,
  },
  {
    pattern: /^Static analysis identified (\d+) threat indicators\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `L'analyse statique a identifie ${match[1]} indicateurs de menace.`
        : `حدد التحليل الثابت ${match[1]} مؤشرات تهديد.`,
  },
  {
    pattern: /^Latest dynamic score: (\d+)\/100 after (\d+)s of execution\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `Dernier score dynamique : ${match[1]}/100 apres ${match[2]}s d'execution.`
        : `اخر درجة ديناميكية: ${match[1]}/100 بعد ${match[2]} ثانية من التنفيذ.`,
  },
  {
    pattern: /^Dynamic run observed (\d+) network connection attempts\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `L'execution dynamique a observe ${match[1]} tentatives de connexion reseau.`
        : `رصد التنفيذ الديناميكي ${match[1]} محاولات اتصال شبكي.`,
  },
  {
    pattern: /^Content analysis found (\d+) suspicious indicators\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `L'analyse du contenu a trouve ${match[1]} indicateurs suspects.`
        : `وجد تحليل المحتوى ${match[1]} مؤشرات مشبوهة.`,
  },
  {
    pattern: /^Enter (MD5|SHA1|SHA256) hash \(e\.g\., (.+)\)$/,
    render: (match, language) =>
      language === 'fr'
        ? `Entrez le hash ${match[1]} (ex. : ${match[2]})`
        : `ادخل بصمة ${match[1]} (مثال: ${match[2]})`,
  },
];

const LanguageContext = createContext<LanguageContextType | undefined>(undefined);

const EXCLUDED_TAGS = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'CODE', 'PRE']);

function normalizeLiteralKey(value: string): string {
  return value.replace(/\s+/g, ' ').trim();
}

function preserveWhitespace(original: string, translated: string): string {
  const leading = original.match(/^\s*/)?.[0] ?? '';
  const trailing = original.match(/\s*$/)?.[0] ?? '';
  return `${leading}${translated}${trailing}`;
}

function replaceLiteralFragments(text: string, language: Exclude<Language, 'en'>): string {
  const replacements = Object.entries(literalTranslations)
    .map(([source, translations]) => [source, translations[language]] as const)
    .filter((entry): entry is [string, string] => Boolean(entry[1]))
    .sort((a, b) => b[0].length - a[0].length);

  let output = text;
  for (const [source, translated] of replacements) {
    if (!source || source === translated) {
      continue;
    }
    output = output.split(source).join(translated);
  }
  return output;
}

function translateLiteral(text: string, language: Language): string {
  if (language === 'en') {
    return text;
  }

  const normalized = normalizeLiteralKey(text);
  if (!normalized) {
    return text;
  }

  const exact = literalTranslations[normalized]?.[language];
  if (exact) {
    return preserveWhitespace(text, exact);
  }

  for (const rule of regexTranslations) {
    const match = rule.pattern.exec(normalized);
    if (match) {
      return preserveWhitespace(text, rule.render(match, language));
    }
  }

  const partial = replaceLiteralFragments(text, language);
  return partial === text ? text : preserveWhitespace(text, partial.trim());
}

function shouldIgnoreNode(node: Node | null): boolean {
  if (!node) {
    return true;
  }
  const parent = node.parentElement;
  if (!parent) {
    return true;
  }
  if (EXCLUDED_TAGS.has(parent.tagName)) {
    return true;
  }
  if (parent.closest('[data-no-i18n="true"]')) {
    return true;
  }
  if (parent.closest('[contenteditable="true"]')) {
    return true;
  }
  return false;
}

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [language, setLanguageState] = useState<Language>(() => {
    const stored = localStorage.getItem(STORAGE_KEY) as Language | null;
    return stored && ['en', 'fr', 'ar'].includes(stored) ? stored : 'en';
  });
  const textOriginalsRef = useRef(new WeakMap<Node, string>());
  const attrOriginalsRef = useRef(new WeakMap<Element, Record<string, string>>());

  const isRtl = language === 'ar';

  useEffect(() => {
    document.documentElement.lang = language;
    document.documentElement.dir = isRtl ? 'rtl' : 'ltr';
    localStorage.setItem(STORAGE_KEY, language);
  }, [isRtl, language]);

  useEffect(() => {
    const textOriginals = textOriginalsRef.current;
    const attrOriginals = attrOriginalsRef.current;

    const translateTextNode = (node: Node) => {
      if (node.nodeType !== Node.TEXT_NODE || shouldIgnoreNode(node)) {
        return;
      }

      const currentValue = node.textContent ?? '';
      const previousOriginal = textOriginals.get(node);

      if (!previousOriginal) {
        textOriginals.set(node, currentValue);
      } else {
        const translatedPrevious = translateLiteral(previousOriginal, language);
        if (currentValue !== previousOriginal && currentValue !== translatedPrevious) {
          textOriginals.set(node, currentValue);
        }
      }

      const source = textOriginals.get(node) ?? currentValue;
      const translated = translateLiteral(source, language);
      if (node.textContent !== translated) {
        node.textContent = translated;
      }
    };

    const translateAttributes = (element: Element) => {
      if (element.closest('[data-no-i18n="true"]')) {
        return;
      }

      const translatableAttributes = ['placeholder', 'title', 'aria-label'];
      const currentMap = attrOriginals.get(element) ?? {};

      for (const attr of translatableAttributes) {
        const currentValue = element.getAttribute(attr);
        if (!currentValue) {
          continue;
        }

        const previousOriginal = currentMap[attr];
        if (!previousOriginal) {
          currentMap[attr] = currentValue;
        } else {
          const translatedPrevious = translateLiteral(previousOriginal, language);
          if (currentValue !== previousOriginal && currentValue !== translatedPrevious) {
            currentMap[attr] = currentValue;
          }
        }

        const translated = translateLiteral(currentMap[attr], language);
        if (translated !== currentValue) {
          element.setAttribute(attr, translated);
        }
      }

      attrOriginals.set(element, currentMap);
    };

    const translateTree = (root: Node) => {
      if (root.nodeType === Node.TEXT_NODE) {
        translateTextNode(root);
        return;
      }

      if (root.nodeType !== Node.ELEMENT_NODE && root.nodeType !== Node.DOCUMENT_FRAGMENT_NODE) {
        return;
      }

      if (root.nodeType === Node.ELEMENT_NODE) {
        translateAttributes(root as Element);
      }

      const walker = document.createTreeWalker(root, NodeFilter.SHOW_ALL);
      let current: Node | null = walker.currentNode;
      while (current) {
        if (current.nodeType === Node.TEXT_NODE) {
          translateTextNode(current);
        } else if (current.nodeType === Node.ELEMENT_NODE) {
          translateAttributes(current as Element);
        }
        current = walker.nextNode();
      }
    };

    if (document.body) {
      translateTree(document.body);
    }

    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === 'characterData') {
          translateTextNode(mutation.target);
          continue;
        }

        mutation.addedNodes.forEach((node) => {
          translateTree(node);
        });

        if (mutation.type === 'attributes' && mutation.target instanceof Element) {
          translateAttributes(mutation.target);
        }
      }
    });

    if (document.body) {
      observer.observe(document.body, {
        childList: true,
        subtree: true,
        characterData: true,
        attributes: true,
        attributeFilter: ['placeholder', 'title', 'aria-label'],
      });
    }

    return () => observer.disconnect();
  }, [language]);

  const value = useMemo<LanguageContextType>(
    () => ({
      language,
      isRtl,
      setLanguage: setLanguageState,
      t: (key: string, fallback?: string) => keyTranslations[key]?.[language] ?? fallback ?? key,
      translateText: (text: string) => translateLiteral(text, language),
    }),
    [isRtl, language]
  );

  return <LanguageContext.Provider value={value}>{children}</LanguageContext.Provider>;
}

export function useLanguage() {
  const context = useContext(LanguageContext);
  if (!context) {
    throw new Error('useLanguage must be used within a LanguageProvider');
  }
  return context;
}
