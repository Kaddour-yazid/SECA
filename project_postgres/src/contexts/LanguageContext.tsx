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
    ar: 'Ø§Ù„Ø§Ø¹Ø¯Ø§Ø¯Ø§Øª',
  },
  'settings.title': {
    en: 'Parameters',
    fr: 'Parametres',
    ar: 'Ø§Ù„Ø§Ø¹Ø¯Ø§Ø¯Ø§Øª',
  },
  'settings.subtitle': {
    en: 'Choose the interface language.',
    fr: "Choisissez la langue de l'interface.",
    ar: 'Ø§Ø®ØªØ± Ù„ØºØ© Ø§Ù„ÙˆØ§Ø¬Ù‡Ø©.',
  },
  'settings.language': {
    en: 'Language',
    fr: 'Langue',
    ar: 'Ø§Ù„Ù„ØºØ©',
  },
  'settings.appearance': {
    en: 'Appearance',
    fr: 'Apparence',
    ar: 'Ø§Ù„Ù…Ø¸Ù‡Ø±',
  },
  'settings.account': {
    en: 'Account',
    fr: 'Compte',
    ar: 'Ø§Ù„Ø­Ø³Ø§Ø¨',
  },
  'settings.logout': {
    en: 'Logout',
    fr: 'Se deconnecter',
    ar: 'ØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ø®Ø±ÙˆØ¬',
  },
  'settings.close': {
    en: 'Close',
    fr: 'Fermer',
    ar: 'Ø§ØºÙ„Ø§Ù‚',
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
    ar: 'Ø§Ù„Ø¹Ø±Ø¨ÙŠØ©',
  },
};

const literalTranslations: LiteralDictionary = {
  Parameters: { fr: 'Parametres', ar: 'Ø§Ù„Ø§Ø¹Ø¯Ø§Ø¯Ø§Øª' },
  'Manage your language, appearance, account, and session from one place.': { fr: 'Gerez votre langue, apparence, compte et session depuis un seul endroit.', ar: 'Ø§Ø¯ÙØ± Ù„ØºØªÙƒ ÙˆÙ…Ø¸Ù‡Ø± Ø§Ù„ÙˆØ§Ø¬Ù‡Ø© ÙˆØ­Ø³Ø§Ø¨Ùƒ ÙˆØ¬Ù„Ø³ØªÙƒ Ù…Ù† Ù…ÙƒØ§Ù† ÙˆØ§Ø­Ø¯.' },
  'Language Settings': { fr: 'Parametres de langue', ar: 'Ø§Ø¹Ø¯Ø§Ø¯Ø§Øª Ø§Ù„Ù„ØºØ©' },
  'Appearance Settings': { fr: "Parametres d'apparence", ar: 'Ø§Ø¹Ø¯Ø§Ø¯Ø§Øª Ø§Ù„Ù…Ø¸Ù‡Ø±' },
  'Switch between light and dark mode.': { fr: 'Basculez entre le mode clair et le mode sombre.', ar: 'Ø¨Ø¯Ù„ Ø¨ÙŠÙ† Ø§Ù„ÙˆØ¶Ø¹ Ø§Ù„ÙØ§ØªØ­ ÙˆØ§Ù„ÙˆØ¶Ø¹ Ø§Ù„Ø¯Ø§ÙƒÙ†.' },
  'Review your current account information.': { fr: 'Consultez les informations de votre compte actuel.', ar: 'Ø±Ø§Ø¬Ø¹ Ù…Ø¹Ù„ÙˆÙ…Ø§Øª Ø­Ø³Ø§Ø¨Ùƒ Ø§Ù„Ø­Ø§Ù„ÙŠ.' },
  Logout: { fr: 'Se deconnecter', ar: 'ØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ø®Ø±ÙˆØ¬' },
  'End the current session securely.': { fr: 'Terminez la session en cours en toute securite.', ar: 'Ø§Ù†Ù‡Ù Ø§Ù„Ø¬Ù„Ø³Ø© Ø§Ù„Ø­Ø§Ù„ÙŠØ© Ø¨Ø´ÙƒÙ„ Ø¢Ù…Ù†.' },
  'Select the language used across the SECA interface.': { fr: "Selectionnez la langue utilisee dans l'interface SECA.", ar: 'Ø§Ø®ØªØ± Ø§Ù„Ù„ØºØ© Ø§Ù„Ù…Ø³ØªØ®Ø¯Ù…Ø© ÙÙŠ ÙˆØ§Ø¬Ù‡Ø© SECA.' },
  'Choose how the platform should look on this device.': { fr: "Choisissez l'apparence de la plateforme sur cet appareil.", ar: 'Ø§Ø®ØªØ± ÙƒÙŠÙ ÙŠØ¨Ø¯Ùˆ Ø§Ù„Ù†Ø¸Ø§Ù… Ø¹Ù„Ù‰ Ù‡Ø°Ø§ Ø§Ù„Ø¬Ù‡Ø§Ø².' },
  'Use a brighter interface.': { fr: 'Utiliser une interface plus claire.', ar: 'Ø§Ø³ØªØ®Ø¯Ù… ÙˆØ§Ø¬Ù‡Ø© Ø§ÙƒØ«Ø± Ø³Ø·ÙˆØ¹Ø§.' },
  'Use a darker interface.': { fr: 'Utiliser une interface plus sombre.', ar: 'Ø§Ø³ØªØ®Ø¯Ù… ÙˆØ§Ø¬Ù‡Ø© Ø§Ø¯ÙƒÙ†.' },
  'Current account information for the active session.': { fr: 'Informations du compte actif pour la session en cours.', ar: 'Ù…Ø¹Ù„ÙˆÙ…Ø§Øª Ø§Ù„Ø­Ø³Ø§Ø¨ Ø§Ù„Ù†Ø´Ø· Ù„Ù„Ø¬Ù„Ø³Ø© Ø§Ù„Ø­Ø§Ù„ÙŠØ©.' },
  Role: { fr: 'Role', ar: 'Ø§Ù„Ø¯ÙˆØ±' },
  'More account options will be added here.': { fr: "D'autres options de compte seront ajoutees ici.", ar: 'Ø³ØªØ¶Ø§Ù Ø®ÙŠØ§Ø±Ø§Øª Ø­Ø³Ø§Ø¨ Ø§Ø®Ø±Ù‰ Ù‡Ù†Ø§.' },
  'For now, this section shows the active account and lets you manage language, theme, and logout from this page.': { fr: 'Pour le moment, cette section affiche le compte actif et vous permet de gerer la langue, le theme et la deconnexion depuis cette page.', ar: 'Ø­Ø§Ù„ÙŠØ§ØŒ ÙŠØ¹Ø±Ø¶ Ù‡Ø°Ø§ Ø§Ù„Ù‚Ø³Ù… Ø§Ù„Ø­Ø³Ø§Ø¨ Ø§Ù„Ù†Ø´Ø· ÙˆÙŠØªÙŠØ­ Ù„Ùƒ Ø§Ø¯Ø§Ø±Ø© Ø§Ù„Ù„ØºØ© ÙˆØ§Ù„Ù…Ø¸Ù‡Ø± ÙˆØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ø®Ø±ÙˆØ¬ Ù…Ù† Ù‡Ø°Ù‡ Ø§Ù„ØµÙØ­Ø©.' },
  Appearance: { fr: 'Apparence', ar: 'Ø§Ù„Ù…Ø¸Ù‡Ø±' },
  'Open Parameters to change language, theme, account, or logout.': { fr: 'Ouvrez Parametres pour changer la langue, le theme, le compte ou la deconnexion.', ar: 'Ø§ÙØªØ­ Ø§Ù„Ø§Ø¹Ø¯Ø§Ø¯Ø§Øª Ù„ØªØºÙŠÙŠØ± Ø§Ù„Ù„ØºØ© ÙˆØ§Ù„Ù…Ø¸Ù‡Ø± ÙˆØ§Ù„Ø­Ø³Ø§Ø¨ Ø§Ùˆ ØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ø®Ø±ÙˆØ¬.' },
  Dashboard: { fr: 'Tableau de bord', ar: 'Ù„ÙˆØ­Ø© Ø§Ù„ØªØ­ÙƒÙ…' },
  'File Scanner': { fr: 'Analyseur de fichiers', ar: 'ÙØ§Ø­Øµ Ø§Ù„Ù…Ù„ÙØ§Øª' },
  'URL Scanner': { fr: "Analyseur d'URL", ar: 'ÙØ§Ø­Øµ Ø§Ù„Ø±ÙˆØ§Ø¨Ø·' },
  'Email Scanner': { fr: "Analyseur d'emails", ar: 'ÙØ§Ø­Øµ Ø§Ù„Ø¨Ø±ÙŠØ¯ Ø§Ù„Ø¥Ù„ÙƒØªØ±ÙˆÙ†ÙŠ' },
  'Hash Checker': { fr: 'Verificateur de hash', ar: 'ÙØ§Ø­Øµ Ø§Ù„Ø¨ØµÙ…Ø©' },
  Monitoring: { fr: 'Surveillance', ar: 'Ø§Ù„Ù…Ø±Ø§Ù‚Ø¨Ø©' },
  'Audit Logs': { fr: "Journaux d'audit", ar: 'Ø³Ø¬Ù„Ø§Øª Ø§Ù„ØªØ¯Ù‚ÙŠÙ‚' },
  'Access Control': { fr: "Controle d'acces", ar: 'Ø§Ù„ØªØ­ÙƒÙ… ÙÙŠ Ø§Ù„ÙˆØµÙˆÙ„' },
  'Security Analyzer': { fr: 'Analyseur de securite', ar: 'Ù…Ø­Ù„Ù„ Ø§Ù„Ø§Ù…Ø§Ù†' },
  Admin: { fr: 'Admin', ar: 'Ù…Ø³Ø¤ÙˆÙ„' },
  User: { fr: 'Utilisateur', ar: 'Ù…Ø³ØªØ®Ø¯Ù…' },
  'Light Mode': { fr: 'Mode clair', ar: 'Ø§Ù„ÙˆØ¶Ø¹ Ø§Ù„ÙØ§ØªØ­' },
  'Dark Mode': { fr: 'Mode sombre', ar: 'Ø§Ù„ÙˆØ¶Ø¹ Ø§Ù„Ø¯Ø§ÙƒÙ†' },
  'Sign Out': { fr: 'Se deconnecter', ar: 'ØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ø®Ø±ÙˆØ¬' },
  'SECA Platform': { fr: 'Plateforme SECA', ar: 'Ù…Ù†ØµØ© SECA' },
  'SECA platform access': { fr: 'Connexion a la plateforme SECA', ar: 'Ø§Ù„Ø¯Ø®ÙˆÙ„ Ø§Ù„Ù‰ Ù…Ù†ØµØ© SECA' },
  'Secure access': { fr: 'Acces securise', ar: 'ÙˆØµÙˆÙ„ Ø¢Ù…Ù†' },
  Restricted: { fr: 'Restreint', ar: 'Ù…Ù‚ÙŠØ¯' },
  Active: { fr: 'Actif', ar: 'Ù†Ø´Ø·' },
  Review: { fr: 'Revue', ar: 'Ù…Ø±Ø§Ø¬Ø¹Ø©' },
  Logged: { fr: 'Journalise', ar: 'Ù…Ø³Ø¬Ù„' },
  'Security notice': { fr: 'Notice de securite', ar: 'Ù…Ù„Ø§Ø­Ø¸Ø© Ø§Ù…Ù†ÙŠØ©' },
  'SECA activity preview': { fr: "Apercu d'activite SECA", ar: 'Ù…Ø¹Ø§ÙŠÙ†Ø© Ù†Ø´Ø§Ø· SECA' },
  'Monitoring and audit workflows': { fr: "Flux de supervision et d'audit", ar: 'Ù…Ø³Ø§Ø±Ø§Øª Ø§Ù„Ù…Ø±Ø§Ù‚Ø¨Ø© ÙˆØ§Ù„ØªØ¯Ù‚ÙŠÙ‚' },
  'URL scan queued': { fr: "Scan d'URL en attente", ar: 'ÙØ­Øµ Ø§Ù„Ø±Ø§Ø¨Ø· ÙÙŠ Ø§Ù„Ø§Ù†ØªØ¸Ø§Ø±' },
  'Gateway policy hit': { fr: 'Regle passerelle declenchee', ar: 'ØªÙ… ØªÙØ¹ÙŠÙ„ Ø³ÙŠØ§Ø³Ø© Ø§Ù„Ø¨ÙˆØ§Ø¨Ø©' },
  'Audit trail synced': { fr: "Piste d'audit synchronisee", ar: 'ØªÙ…Øª Ù…Ø²Ø§Ù…Ù†Ø© Ø³Ø¬Ù„ Ø§Ù„ØªØ¯Ù‚ÙŠÙ‚' },
  'Restricted system access': { fr: 'Acces systeme restreint', ar: 'ÙˆØµÙˆÙ„ Ø§Ù„Ù†Ø¸Ø§Ù… Ù…Ù‚ÙŠØ¯' },
  'Authorized personnel only': { fr: 'Personnel autorise uniquement', ar: 'Ù„Ù„Ù…Ø®ÙˆÙ„ÙŠÙ† ÙÙ‚Ø·' },
  'Internal system': { fr: 'Systeme interne', ar: 'Ù†Ø¸Ø§Ù… Ø¯Ø§Ø®Ù„ÙŠ' },
  'Internal security analysis environment': { fr: "Environnement interne d'analyse de securite", ar: 'Ø¨ÙŠØ¦Ø© Ø¯Ø§Ø®Ù„ÙŠØ© Ù„ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ø§Ù…Ù†' },
  'Restricted access to SECA analysis, supervision, and audit workflows.': { fr: "Acces restreint aux flux SECA d'analyse, de supervision et d'audit.", ar: 'ÙˆØµÙˆÙ„ Ù…Ù‚ÙŠØ¯ Ø§Ù„Ù‰ Ù…Ø³Ø§Ø±Ø§Øª SECA Ø§Ù„Ø®Ø§ØµØ© Ø¨Ø§Ù„ØªØ­Ù„ÙŠÙ„ ÙˆØ§Ù„Ù…Ø±Ø§Ù‚Ø¨Ø© ÙˆØ§Ù„ØªØ¯Ù‚ÙŠÙ‚.' },
  'Internal security operations portal': { fr: 'Portail interne des operations de securite', ar: 'Ø¨ÙˆØ§Ø¨Ø© Ø¯Ø§Ø®Ù„ÙŠØ© Ù„Ø¹Ù…Ù„ÙŠØ§Øª Ø§Ù„Ø§Ù…Ù†' },
  'Internal security operations portal for scanning, monitoring, and audit workflows.': { fr: "Plateforme interne d'analyse, de supervision et d'audit en cybersecurite.", ar: 'Ù…Ù†ØµØ© Ø¯Ø§Ø®Ù„ÙŠØ© Ù„Ø¹Ù…Ù„ÙŠØ§Øª Ø§Ù„ÙØ­Øµ ÙˆØ§Ù„Ù…Ø±Ø§Ù‚Ø¨Ø© ÙˆØ§Ù„ØªØ¯Ù‚ÙŠÙ‚ Ø§Ù„Ø§Ù…Ù†ÙŠ.' },
  'Account Security': { fr: 'Securite du compte', ar: 'Ø§Ù…Ø§Ù† Ø§Ù„Ø­Ø³Ø§Ø¨' },
  'Create your SECA account': { fr: 'Creer votre compte SECA', ar: 'Ø§Ù†Ø´Ø¦ Ø­Ø³Ø§Ø¨ SECA Ø§Ù„Ø®Ø§Øµ Ø¨Ùƒ' },
  'Create Account': { fr: 'Creer un compte', ar: 'Ø§Ù†Ø´Ø§Ø¡ Ø­Ø³Ø§Ø¨' },
  'Verify your email': { fr: 'Verifiez votre email', ar: 'ØªØ­Ù‚Ù‚ Ù…Ù† Ø¨Ø±ÙŠØ¯Ùƒ Ø§Ù„Ø§Ù„ÙƒØªØ±ÙˆÙ†ÙŠ' },
  'Verify Email': { fr: "Verifier l'email", ar: 'ØªØ£ÙƒÙŠØ¯ Ø§Ù„Ø¨Ø±ÙŠØ¯ Ø§Ù„Ø§Ù„ÙƒØªØ±ÙˆÙ†ÙŠ' },
  'Recover access': { fr: "Recuperer l'acces", ar: 'Ø§Ø³ØªØ¹Ø§Ø¯Ø© Ø§Ù„ÙˆØµÙˆÙ„' },
  'Recover Password': { fr: 'Recuperer le mot de passe', ar: 'Ø§Ø³ØªØ¹Ø§Ø¯Ø© ÙƒÙ„Ù…Ø© Ø§Ù„Ù…Ø±ÙˆØ±' },
  'Set a new password': { fr: 'Definir un nouveau mot de passe', ar: 'ØªØ¹ÙŠÙŠÙ† ÙƒÙ„Ù…Ø© Ù…Ø±ÙˆØ± Ø¬Ø¯ÙŠØ¯Ø©' },
  'Set New Password': { fr: 'Definir un nouveau mot de passe', ar: 'ØªØ¹ÙŠÙŠÙ† ÙƒÙ„Ù…Ø© Ù…Ø±ÙˆØ± Ø¬Ø¯ÙŠØ¯Ø©' },
  'Welcome back': { fr: 'Bon retour', ar: 'Ù…Ø±Ø­Ø¨Ø§ Ø¨Ø¹ÙˆØ¯ØªÙƒ' },
  'Sign In': { fr: 'Se connecter', ar: 'ØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ø¯Ø®ÙˆÙ„' },
  'Sign Up': { fr: "S'inscrire", ar: 'Ø§Ù†Ø´Ø§Ø¡ Ø­Ø³Ø§Ø¨' },
  Back: { fr: 'Retour', ar: 'Ø±Ø¬ÙˆØ¹' },
  Email: { fr: 'Email', ar: 'Ø§Ù„Ø¨Ø±ÙŠØ¯ Ø§Ù„Ø§Ù„ÙƒØªØ±ÙˆÙ†ÙŠ' },
  Password: { fr: 'Mot de passe', ar: 'ÙƒÙ„Ù…Ø© Ø§Ù„Ù…Ø±ÙˆØ±' },
  'Create Password': { fr: 'Creer un mot de passe', ar: 'Ø§Ù†Ø´Ø§Ø¡ ÙƒÙ„Ù…Ø© Ù…Ø±ÙˆØ±' },
  'One-Time Code': { fr: 'Code unique', ar: 'Ø±Ù…Ø² Ù„Ù…Ø±Ø© ÙˆØ§Ø­Ø¯Ø©' },
  'New Password': { fr: 'Nouveau mot de passe', ar: 'ÙƒÙ„Ù…Ø© Ù…Ø±ÙˆØ± Ø¬Ø¯ÙŠØ¯Ø©' },
  'Send Verification Code': { fr: 'Envoyer le code de verification', ar: 'Ø§Ø±Ø³Ø§Ù„ Ø±Ù…Ø² Ø§Ù„ØªØ­Ù‚Ù‚' },
  'Verify and Create Account': { fr: 'Verifier et creer le compte', ar: 'ØªØ­Ù‚Ù‚ ÙˆØ§Ù†Ø´Ø¦ Ø§Ù„Ø­Ø³Ø§Ø¨' },
  'Send Reset Code': { fr: 'Envoyer le code de reinitialisation', ar: 'Ø§Ø±Ø³Ø§Ù„ Ø±Ù…Ø² Ø§Ø¹Ø§Ø¯Ø© Ø§Ù„ØªØ¹ÙŠÙŠÙ†' },
  'Update Password': { fr: 'Mettre a jour le mot de passe', ar: 'ØªØ­Ø¯ÙŠØ« ÙƒÙ„Ù…Ø© Ø§Ù„Ù…Ø±ÙˆØ±' },
  'Back to sign in': { fr: 'Retour a la connexion', ar: 'Ø§Ù„Ø¹ÙˆØ¯Ø© Ù„ØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ø¯Ø®ÙˆÙ„' },
  'Forgot password?': { fr: 'Mot de passe oublie ?', ar: 'Ù‡Ù„ Ù†Ø³ÙŠØª ÙƒÙ„Ù…Ø© Ø§Ù„Ù…Ø±ÙˆØ±ØŸ' },
  'Create one here': { fr: 'Creez-en un ici', ar: 'Ø§Ù†Ø´Ø¦ ÙˆØ§Ø­Ø¯Ø§ Ù‡Ù†Ø§' },
  'Sign in here': { fr: 'Connectez-vous ici', ar: 'Ø³Ø¬Ù„ Ø§Ù„Ø¯Ø®ÙˆÙ„ Ù‡Ù†Ø§' },
  "Don't have an account?": { fr: "Vous n'avez pas de compte ?", ar: 'Ù„ÙŠØ³ Ù„Ø¯ÙŠÙƒ Ø­Ø³Ø§Ø¨ØŸ' },
  'Already have an account?': { fr: 'Vous avez deja un compte ?', ar: 'Ù„Ø¯ÙŠÙƒ Ø­Ø³Ø§Ø¨ Ø¨Ø§Ù„ÙØ¹Ù„ØŸ' },
  'Show password': { fr: 'Afficher le mot de passe', ar: 'Ø§Ø¸Ù‡Ø§Ø± ÙƒÙ„Ù…Ø© Ø§Ù„Ù…Ø±ÙˆØ±' },
  'Hide password': { fr: 'Masquer le mot de passe', ar: 'Ø§Ø®ÙØ§Ø¡ ÙƒÙ„Ù…Ø© Ø§Ù„Ù…Ø±ÙˆØ±' },
  'Processing...': { fr: 'Traitement...', ar: 'Ø¬Ø§Ø± Ø§Ù„Ù…Ø¹Ø§Ù„Ø¬Ø©...' },
  'Login successful. Redirecting...': { fr: 'Connexion reussie. Redirection...', ar: 'ØªÙ… ØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ø¯Ø®ÙˆÙ„ Ø¨Ù†Ø¬Ø§Ø­. Ø¬Ø§Ø± Ø§Ù„ØªØ­ÙˆÙŠÙ„...' },
  'Email verified. You can now sign in with your password.': { fr: 'Email verifie. Vous pouvez maintenant vous connecter avec votre mot de passe.', ar: 'ØªÙ… Ø§Ù„ØªØ­Ù‚Ù‚ Ù…Ù† Ø§Ù„Ø¨Ø±ÙŠØ¯. ÙŠÙ…ÙƒÙ†Ùƒ Ø§Ù„Ø§Ù† ØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ø¯Ø®ÙˆÙ„ Ø¨ÙƒÙ„Ù…Ø© Ø§Ù„Ù…Ø±ÙˆØ±.' },
  'Password updated. Sign in with the new password.': { fr: 'Mot de passe mis a jour. Connectez-vous avec le nouveau mot de passe.', ar: 'ØªÙ… ØªØ­Ø¯ÙŠØ« ÙƒÙ„Ù…Ø© Ø§Ù„Ù…Ø±ÙˆØ±. Ø³Ø¬Ù„ Ø§Ù„Ø¯Ø®ÙˆÙ„ Ø¨ÙƒÙ„Ù…Ø© Ø§Ù„Ù…Ø±ÙˆØ± Ø§Ù„Ø¬Ø¯ÙŠØ¯Ø©.' },
  'Authentication failed': { fr: "Echec de l'authentification", ar: 'ÙØ´Ù„Øª Ø§Ù„Ù…ØµØ§Ø¯Ù‚Ø©' },
  'your@email.com': { fr: 'votre@email.com', ar: 'your@email.com' },
  'Minimum 8 characters': { fr: '8 caracteres minimum', ar: '8 Ø§Ø­Ø±Ù Ø¹Ù„Ù‰ Ø§Ù„Ø§Ù‚Ù„' },
  'Platform scope': { fr: 'Portee de la plateforme', ar: 'Ù†Ø·Ø§Ù‚ Ø§Ù„Ù…Ù†ØµØ©' },
  'Static and dynamic scan workflows': { fr: 'Flux de scan statique et dynamique', ar: 'Ù…Ø³Ø§Ø±Ø§Øª ÙØ­Øµ Ø«Ø§Ø¨ØªØ© ÙˆØ¯ÙŠÙ†Ø§Ù…ÙŠÙƒÙŠØ©' },
  'Gateway supervision and audit visibility': { fr: 'Supervision de passerelle et visibilite audit', ar: 'Ø§Ø´Ø±Ø§Ù Ø¹Ù„Ù‰ Ø§Ù„Ø¨ÙˆØ§Ø¨Ø© ÙˆØ±Ø¤ÙŠØ© Ø³Ø¬Ù„Ø§Øª Ø§Ù„ØªØ¯Ù‚ÙŠÙ‚' },
  'Internal operations only': { fr: 'Operations internes uniquement', ar: 'Ù„Ù„Ø§Ø³ØªØ®Ø¯Ø§Ù… Ø§Ù„Ø¯Ø§Ø®Ù„ÙŠ ÙÙ‚Ø·' },
  'Static and sandbox inspection': { fr: 'Inspection statique et sandbox', ar: 'ÙØ­Øµ Ø«Ø§Ø¨Øª ÙˆØ¯Ø§Ø®Ù„ Ø§Ù„Ø³Ø§Ù†Ø¯Ø¨ÙˆÙƒØ³' },
  'Reputation and content controls': { fr: 'Controles de reputation et de contenu', ar: 'Ø¶ÙˆØ§Ø¨Ø· Ø§Ù„Ø³Ù…Ø¹Ø© ÙˆØ§Ù„Ù…Ø­ØªÙˆÙ‰' },
  'Fast verdict against known indicators': { fr: 'Verdict rapide contre les indicateurs connus', ar: 'Ø­ÙƒÙ… Ø³Ø±ÙŠØ¹ Ù…Ù‚Ø§Ø¨Ù„ Ø§Ù„Ù…Ø¤Ø´Ø±Ø§Øª Ø§Ù„Ù…Ø¹Ø±ÙˆÙØ©' },
  'Traceability for monitored actions': { fr: 'TraÃ§abilite des actions supervisees', ar: 'Ù‚Ø§Ø¨Ù„ÙŠØ© ØªØªØ¨Ø¹ Ø§Ù„Ø§Ø¬Ø±Ø§Ø¡Ø§Øª Ø§Ù„Ø®Ø§Ø¶Ø¹Ø© Ù„Ù„Ù…Ø±Ø§Ù‚Ø¨Ø©' },
  'Security analysis, monitoring, and access control from one workspace.': { fr: 'Analyse de securite, surveillance et controle d acces depuis un seul espace de travail.', ar: 'ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ø§Ù…Ø§Ù† ÙˆØ§Ù„Ù…Ø±Ø§Ù‚Ø¨Ø© ÙˆØ§Ù„ØªØ­ÙƒÙ… ÙÙŠ Ø§Ù„ÙˆØµÙˆÙ„ Ù…Ù† Ù…Ø³Ø§Ø­Ø© Ø¹Ù…Ù„ ÙˆØ§Ø­Ø¯Ø©.' },
  'Multi-layer threat analysis': { fr: 'Analyse des menaces multi-couches', ar: 'ØªØ­Ù„ÙŠÙ„ Ø§Ù„ØªÙ‡Ø¯ÙŠØ¯Ø§Øª Ù…ØªØ¹Ø¯Ø¯ Ø§Ù„Ø·Ø¨Ù‚Ø§Øª' },
  'Analyze files, URLs, hashes, and emails with unified verdicts and detailed reports.': { fr: 'Analysez les fichiers, URL, hashes et emails avec des verdicts unifies et des rapports detailles.', ar: 'Ø­Ù„Ù„ Ø§Ù„Ù…Ù„ÙØ§Øª ÙˆØ§Ù„Ø±ÙˆØ§Ø¨Ø· ÙˆØ§Ù„Ø¨ØµÙ…Ø§Øª ÙˆØ§Ù„Ø¨Ø±ÙŠØ¯ Ù…Ø¹ Ù†ØªØ§Ø¦Ø¬ Ù…ÙˆØ­Ø¯Ø© ÙˆØªÙ‚Ø§Ø±ÙŠØ± Ù…ÙØµÙ„Ø©.' },
  'Monitoring and enforcement': { fr: 'Surveillance et application', ar: 'Ø§Ù„Ù…Ø±Ø§Ù‚Ø¨Ø© ÙˆØ§Ù„ØªÙ†ÙÙŠØ°' },
  'Track gateway activity, review audit logs, and manage policy decisions from the same dashboard.': { fr: 'Suivez l activite de la passerelle, consultez les journaux d audit et gerez les politiques depuis le meme tableau de bord.', ar: 'ØªØ§Ø¨Ø¹ Ù†Ø´Ø§Ø· Ø§Ù„Ø¨ÙˆØ§Ø¨Ø© ÙˆØ±Ø§Ø¬Ø¹ Ø³Ø¬Ù„Ø§Øª Ø§Ù„ØªØ¯Ù‚ÙŠÙ‚ ÙˆØ§Ø¯ÙØ± Ø§Ù„Ø³ÙŠØ§Ø³Ø§Øª Ù…Ù† Ù†ÙØ³ Ø§Ù„Ù„ÙˆØ­Ø©.' },
  'Verify ownership of your email before the account is created.': { fr: "Verifiez la propriete de votre email avant la creation du compte.", ar: 'ØªØ­Ù‚Ù‚ Ù…Ù† Ù…Ù„ÙƒÙŠØ© Ø¨Ø±ÙŠØ¯Ùƒ Ù‚Ø¨Ù„ Ø§Ù†Ø´Ø§Ø¡ Ø§Ù„Ø­Ø³Ø§Ø¨.' },
  'Authenticate to access scanning and monitoring tools.': { fr: "Authentifiez-vous pour acceder aux outils de scan et de supervision.", ar: 'Ù‚Ù… Ø¨Ø§Ù„Ù…ØµØ§Ø¯Ù‚Ø© Ù„Ù„ÙˆØµÙˆÙ„ Ø§Ù„Ù‰ Ø§Ø¯ÙˆØ§Øª Ø§Ù„ÙØ­Øµ ÙˆØ§Ù„Ù…Ø±Ø§Ù‚Ø¨Ø©.' },
  'Enter your email and password to continue.': { fr: 'Entrez votre email et votre mot de passe pour continuer.', ar: 'Ø§Ø¯Ø®Ù„ Ø¨Ø±ÙŠØ¯Ùƒ ÙˆÙƒÙ„Ù…Ø© Ø§Ù„Ù…Ø±ÙˆØ± Ù„Ù„Ù…ØªØ§Ø¨Ø¹Ø©.' },
  'Start with your work email and a secure password.': { fr: 'Commencez avec votre email professionnel et un mot de passe securise.', ar: 'Ø§Ø¨Ø¯Ø£ Ø¨Ø¨Ø±ÙŠØ¯ Ø§Ù„Ø¹Ù…Ù„ ÙˆÙƒÙ„Ù…Ø© Ù…Ø±ÙˆØ± Ø¢Ù…Ù†Ø©.' },
  'Create your account to get started.': { fr: 'Creez votre compte pour commencer.', ar: 'Ø§Ù†Ø´Ø¦ Ø­Ø³Ø§Ø¨Ùƒ Ù„Ù„Ø¨Ø¯Ø¡.' },
  'Enter the verification code sent to your inbox.': { fr: 'Entrez le code de verification envoye dans votre boite mail.', ar: 'Ø§Ø¯Ø®Ù„ Ø±Ù…Ø² Ø§Ù„ØªØ­Ù‚Ù‚ Ø§Ù„Ù…Ø±Ø³Ù„ Ø§Ù„Ù‰ Ø¨Ø±ÙŠØ¯Ùƒ.' },
  'Enter the one-time code sent to your inbox.': { fr: 'Entrez le code unique envoye dans votre boite mail.', ar: 'Ø§Ø¯Ø®Ù„ Ø§Ù„Ø±Ù…Ø² Ø§Ù„Ù…Ø±Ø³Ù„ Ø§Ù„Ù‰ Ø¨Ø±ÙŠØ¯Ùƒ.' },
  'Enter the code sent to your email.': { fr: 'Entrez le code envoye a votre email.', ar: 'Ø§Ø¯Ø®Ù„ Ø§Ù„Ø±Ù…Ø² Ø§Ù„Ù…Ø±Ø³Ù„ Ø§Ù„Ù‰ Ø¨Ø±ÙŠØ¯Ùƒ Ø§Ù„Ø§Ù„ÙƒØªØ±ÙˆÙ†ÙŠ.' },
  'Request a reset code for your SECA account.': { fr: 'Demandez un code de reinitialisation pour votre compte SECA.', ar: 'Ø§Ø·Ù„Ø¨ Ø±Ù…Ø² Ø§Ø¹Ø§Ø¯Ø© ØªØ¹ÙŠÙŠÙ† Ù„Ø­Ø³Ø§Ø¨ SECA Ø§Ù„Ø®Ø§Øµ Ø¨Ùƒ.' },
  'Reset your password securely.': { fr: 'Reinitialisez votre mot de passe en toute securite.', ar: 'Ø§Ø¹Ø¯ ØªØ¹ÙŠÙŠÙ† ÙƒÙ„Ù…Ø© Ø§Ù„Ù…Ø±ÙˆØ± Ø¨Ø´ÙƒÙ„ Ø¢Ù…Ù†.' },
  'Request a reset code for your existing user account.': { fr: 'Demandez un code de reinitialisation pour votre compte existant.', ar: 'Ø§Ø·Ù„Ø¨ Ø±Ù…Ø² Ø§Ø¹Ø§Ø¯Ø© ØªØ¹ÙŠÙŠÙ† Ù„Ø­Ø³Ø§Ø¨Ùƒ Ø§Ù„Ø­Ø§Ù„ÙŠ.' },
  'Choose a new password to restore access.': { fr: "Choisissez un nouveau mot de passe pour restaurer l'acces.", ar: 'Ø§Ø®ØªØ± ÙƒÙ„Ù…Ø© Ù…Ø±ÙˆØ± Ø¬Ø¯ÙŠØ¯Ø© Ù„Ø§Ø³ØªØ¹Ø§Ø¯Ø© Ø§Ù„ÙˆØµÙˆÙ„.' },
  'Use the reset code to assign a new password.': { fr: 'Utilisez le code de reinitialisation pour definir un nouveau mot de passe.', ar: 'Ø§Ø³ØªØ®Ø¯Ù… Ø±Ù…Ø² Ø§Ø¹Ø§Ø¯Ø© Ø§Ù„ØªØ¹ÙŠÙŠÙ† Ù„ØªØ­Ø¯ÙŠØ¯ ÙƒÙ„Ù…Ø© Ù…Ø±ÙˆØ± Ø¬Ø¯ÙŠØ¯Ø©.' },
  'File scanning': { fr: 'Scan de fichiers', ar: 'ÙØ­Øµ Ø§Ù„Ù…Ù„ÙØ§Øª' },
  'URL analysis': { fr: "Analyse d'URL", ar: 'ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ø±ÙˆØ§Ø¨Ø·' },
  'Hash verification': { fr: 'Verification de hash', ar: 'Ø§Ù„ØªØ­Ù‚Ù‚ Ù…Ù† Ø§Ù„Ø¨ØµÙ…Ø©' },
  'Admin audit': { fr: 'Audit administrateur', ar: 'ØªØ¯Ù‚ÙŠÙ‚ Ø§Ù„Ù…Ø³Ø¤ÙˆÙ„' },
  'Internal use only': { fr: 'Usage interne uniquement', ar: 'Ù„Ù„Ø§Ø³ØªØ®Ø¯Ø§Ù… Ø§Ù„Ø¯Ø§Ø®Ù„ÙŠ ÙÙ‚Ø·' },
  'Enter the reset code and choose a new password.': { fr: 'Entrez le code de reinitialisation et choisissez un nouveau mot de passe.', ar: 'Ø§Ø¯Ø®Ù„ Ø±Ù…Ø² Ø§Ø¹Ø§Ø¯Ø© Ø§Ù„ØªØ¹ÙŠÙŠÙ† ÙˆØ§Ø®ØªØ± ÙƒÙ„Ù…Ø© Ù…Ø±ÙˆØ± Ø¬Ø¯ÙŠØ¯Ø©.' },
  'Access your SECA workspace with your verified account.': { fr: 'Accedez a votre espace SECA avec votre compte verifie.', ar: 'Ø§Ø¯Ø®Ù„ Ø§Ù„Ù‰ Ù…Ø³Ø§Ø­Ø© SECA Ø¨Ø­Ø³Ø§Ø¨Ùƒ Ø§Ù„Ù…ÙˆØ«Ù‚.' },
  'Admin accounts are provisioned only by the local admin script.': { fr: "Les comptes admin sont crees uniquement par le script d'administration local.", ar: 'ÙŠØªÙ… Ø§Ù†Ø´Ø§Ø¡ Ø­Ø³Ø§Ø¨Ø§Øª Ø§Ù„Ù…Ø³Ø¤ÙˆÙ„ ÙÙ‚Ø· Ø¹Ø¨Ø± Ø³ÙƒØ±Ø¨Øª Ø§Ù„Ø§Ø¯Ù…Ù† Ø§Ù„Ù…Ø­Ù„ÙŠ.' },
  'Website Access Control': { fr: "Controle d'acces aux sites web", ar: 'Ø§Ù„ØªØ­ÙƒÙ… ÙÙŠ Ø§Ù„ÙˆØµÙˆÙ„ Ù„Ù„Ù…ÙˆØ§Ù‚Ø¹' },
  'Manage blocked domains for all devices using your proxy.': { fr: 'Gerez les domaines bloques pour tous les appareils utilisant votre proxy.', ar: 'Ø§Ø¯ÙØ± Ø§Ù„Ù†Ø·Ø§Ù‚Ø§Øª Ø§Ù„Ù…Ø­Ø¬ÙˆØ¨Ø© Ù„ÙƒÙ„ Ø§Ù„Ø§Ø¬Ù‡Ø²Ø© Ø§Ù„ØªÙŠ ØªØ³ØªØ®Ø¯Ù… Ø§Ù„Ø¨Ø±ÙˆÙƒØ³ÙŠ.' },
  Refresh: { fr: 'Actualiser', ar: 'ØªØ­Ø¯ÙŠØ«' },
  'Add domain or URL': { fr: 'Ajouter un domaine ou une URL', ar: 'Ø§Ø¶Ø§ÙØ© Ù†Ø·Ø§Ù‚ Ø§Ùˆ Ø±Ø§Ø¨Ø·' },
  'example.com or https://example.com/page': { fr: 'example.com ou https://example.com/page', ar: 'example.com Ø§Ùˆ https://example.com/page' },
  'Add Block': { fr: 'Ajouter un blocage', ar: 'Ø§Ø¶Ø§ÙØ© Ø­Ø¸Ø±' },
  'Input is normalized to wildcard format (example: *.domain.com).': { fr: 'La saisie est normalisee au format wildcard (exemple : *.domain.com).', ar: 'ÙŠØªÙ… ØªØ­ÙˆÙŠÙ„ Ø§Ù„Ø§Ø¯Ø®Ø§Ù„ Ø§Ù„Ù‰ ØµÙŠØºØ© wildcard Ù…Ø«Ù„: *.domain.com.' },
  'Active Block Rules': { fr: 'Regles de blocage actives', ar: 'Ù‚ÙˆØ§Ø¹Ø¯ Ø§Ù„Ø­Ø¸Ø± Ø§Ù„Ù†Ø´Ø·Ø©' },
  'Loading rules...': { fr: 'Chargement des regles...', ar: 'Ø¬Ø§Ø± ØªØ­Ù…ÙŠÙ„ Ø§Ù„Ù‚ÙˆØ§Ø¹Ø¯...' },
  'No blocked domains configured yet.': { fr: 'Aucun domaine bloque configure pour le moment.', ar: 'Ù„Ø§ ØªÙˆØ¬Ø¯ Ù†Ø·Ø§Ù‚Ø§Øª Ù…Ø­Ø¬ÙˆØ¨Ø© Ø­ØªÙ‰ Ø§Ù„Ø§Ù†.' },
  'No note': { fr: 'Aucune note', ar: 'Ù„Ø§ ØªÙˆØ¬Ø¯ Ù…Ù„Ø§Ø­Ø¸Ø©' },
  Enabled: { fr: 'Active', ar: 'Ù…ÙØ¹Ù„' },
  Disabled: { fr: 'Desactive', ar: 'Ù…Ø¹Ø·Ù„' },
  Remove: { fr: 'Supprimer', ar: 'Ø§Ø²Ø§Ù„Ø©' },
  'Check file hashes against malware databases': { fr: 'Verifier les hashes des fichiers contre les bases de malwares', ar: 'ØªØ­Ù‚Ù‚ Ù…Ù† Ø¨ØµÙ…Ø§Øª Ø§Ù„Ù…Ù„ÙØ§Øª Ù…Ù‚Ø§Ø¨Ù„ Ù‚ÙˆØ§Ø¹Ø¯ Ø¨ÙŠØ§Ù†Ø§Øª Ø§Ù„Ø¨Ø±Ù…Ø¬ÙŠØ§Øª Ø§Ù„Ø®Ø¨ÙŠØ«Ø©' },
  'Check Hash': { fr: 'Verifier le hash', ar: 'ÙØ­Øµ Ø§Ù„Ø¨ØµÙ…Ø©' },
  'Checking Hash...': { fr: 'Verification du hash...', ar: 'Ø¬Ø§Ø± ÙØ­Øµ Ø§Ù„Ø¨ØµÙ…Ø©...' },
  'Searching malware databases and threat feeds': { fr: 'Recherche dans les bases de malwares et flux de menaces', ar: 'Ø§Ù„Ø¨Ø­Ø« ÙÙŠ Ù‚ÙˆØ§Ø¹Ø¯ Ø¨ÙŠØ§Ù†Ø§Øª Ø§Ù„Ø¨Ø±Ù…Ø¬ÙŠØ§Øª Ø§Ù„Ø®Ø¨ÙŠØ«Ø© ÙˆÙ…ØµØ§Ø¯Ø± Ø§Ù„ØªÙ‡Ø¯ÙŠØ¯' },
  'Scan Complete': { fr: 'Analyse terminee', ar: 'Ø§ÙƒØªÙ…Ù„ Ø§Ù„ÙØ­Øµ' },
  'Hash Value': { fr: 'Valeur du hash', ar: 'Ù‚ÙŠÙ…Ø© Ø§Ù„Ø¨ØµÙ…Ø©' },
  'Hash Type': { fr: 'Type de hash', ar: 'Ù†ÙˆØ¹ Ø§Ù„Ø¨ØµÙ…Ø©' },
  'Found in Database': { fr: 'Trouve dans la base', ar: 'Ù…ÙˆØ¬ÙˆØ¯ ÙÙŠ Ù‚Ø§Ø¹Ø¯Ø© Ø§Ù„Ø¨ÙŠØ§Ù†Ø§Øª' },
  'Detections / Engines': { fr: 'Detections / Moteurs', ar: 'Ø§Ù„ÙƒØ´ÙˆÙØ§Øª / Ø§Ù„Ù…Ø­Ø±ÙƒØ§Øª' },
  'Threat Score': { fr: 'Score de menace', ar: 'Ø¯Ø±Ø¬Ø© Ø§Ù„ØªÙ‡Ø¯ÙŠØ¯' },
  'Malware Detected': { fr: 'Malware detecte', ar: 'ØªÙ… Ø§ÙƒØªØ´Ø§Ù Ø¨Ø±Ù…Ø¬ÙŠØ© Ø®Ø¨ÙŠØ«Ø©' },
  'Malware Family': { fr: 'Famille de malware', ar: 'Ø¹Ø§Ø¦Ù„Ø© Ø§Ù„Ø¨Ø±Ù…Ø¬ÙŠØ© Ø§Ù„Ø®Ø¨ÙŠØ«Ø©' },
  'First Seen': { fr: 'Premiere apparition', ar: 'Ø§ÙˆÙ„ Ø¸Ù‡ÙˆØ±' },
  'Suspicious Indicators': { fr: 'Indicateurs suspects', ar: 'Ù…Ø¤Ø´Ø±Ø§Øª Ù…Ø´Ø¨ÙˆÙ‡Ø©' },
  'No Threats Found': { fr: 'Aucune menace detectee', ar: 'Ù„Ù… ÙŠØªÙ… Ø§Ù„Ø¹Ø«ÙˆØ± Ø¹Ù„Ù‰ ØªÙ‡Ø¯ÙŠØ¯Ø§Øª' },
  'This hash has suspicious characteristics but no confirmed malware. Further analysis recommended.': { fr: 'Ce hash presente des caracteristiques suspectes sans malware confirme. Une analyse complementaire est recommandee.', ar: 'Ù‡Ø°Ù‡ Ø§Ù„Ø¨ØµÙ…Ø© ØªØ­ØªÙˆÙŠ Ø¹Ù„Ù‰ Ø®ØµØ§Ø¦Øµ Ù…Ø´Ø¨ÙˆÙ‡Ø© Ø¨Ø¯ÙˆÙ† ØªØ£ÙƒÙŠØ¯ Ù„Ø¨Ø±Ù…Ø¬ÙŠØ© Ø®Ø¨ÙŠØ«Ø©. ÙŠÙˆØµÙ‰ Ø¨ØªØ­Ù„ÙŠÙ„ Ø§Ø¶Ø§ÙÙŠ.' },
  'This hash was not found in any known malware databases. The file appears to be clean.': { fr: 'Ce hash n a ete trouve dans aucune base de malwares connue. Le fichier semble propre.', ar: 'Ù„Ù… ÙŠØªÙ… Ø§Ù„Ø¹Ø«ÙˆØ± Ø¹Ù„Ù‰ Ù‡Ø°Ù‡ Ø§Ù„Ø¨ØµÙ…Ø© ÙÙŠ Ø§ÙŠ Ù‚Ø§Ø¹Ø¯Ø© Ø¨ÙŠØ§Ù†Ø§Øª Ù…Ø¹Ø±ÙˆÙØ©. ÙŠØ¨Ø¯Ùˆ Ø§Ù„Ù…Ù„Ù Ø³Ù„ÙŠÙ…Ø§.' },
  'Advanced URL Scanner': { fr: "Analyseur d'URL avance", ar: 'ÙØ§Ø­Øµ Ø§Ù„Ø±ÙˆØ§Ø¨Ø· Ø§Ù„Ù…ØªÙ‚Ø¯Ù…' },
  'Email Threat Scanner': { fr: "Analyseur de menaces email", ar: 'ÙØ§Ø­Øµ ØªÙ‡Ø¯ÙŠØ¯Ø§Øª Ø§Ù„Ø¨Ø±ÙŠØ¯' },
  '4-layer security analysis for comprehensive threat detection': { fr: 'Analyse de securite en 4 couches pour une detection complete des menaces', ar: 'ØªØ­Ù„ÙŠÙ„ Ø§Ù…Ù†ÙŠ Ù…Ù† 4 Ø·Ø¨Ù‚Ø§Øª Ù„Ø§ÙƒØªØ´Ø§Ù Ø´Ø§Ù…Ù„ Ù„Ù„ØªÙ‡Ø¯ÙŠØ¯Ø§Øª' },
  'Analyze .eml email files for phishing, spoofing, malicious URLs, and risky attachments': { fr: 'Analysez les fichiers email .eml pour le phishing, le spoofing, les URL malveillantes et les pieces jointes a risque', ar: 'Ø­Ù„Ù„ Ù…Ù„ÙØ§Øª Ø§Ù„Ø¨Ø±ÙŠØ¯ .eml Ù„Ø§ÙƒØªØ´Ø§Ù Ø§Ù„ØªØµÙŠØ¯ ÙˆØ§Ù„Ø§Ù†ØªØ­Ø§Ù„ ÙˆØ§Ù„Ø±ÙˆØ§Ø¨Ø· Ø§Ù„Ø®Ø¨ÙŠØ«Ø© ÙˆØ§Ù„Ù…Ø±ÙÙ‚Ø§Øª Ø§Ù„Ø®Ø·Ø±Ø©' },
  'URL Analysis Layers': { fr: "Couches d'analyse URL", ar: 'Ø·Ø¨Ù‚Ø§Øª ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ø±ÙˆØ§Ø¨Ø·' },
  'Did You Know?': { fr: 'Le saviez-vous ?', ar: 'Ù‡Ù„ ØªØ¹Ù„Ù…ØŸ' },
  'Security fact: every URL is checked through four independent risk layers.': { fr: 'Info securite : chaque URL est verifiee par quatre couches de risque independantes.', ar: 'Ù…Ø¹Ù„ÙˆÙ…Ø© Ø§Ù…Ù†ÙŠØ©: ÙŠØªÙ… ÙØ­Øµ ÙƒÙ„ Ø±Ø§Ø¨Ø· Ø¹Ø¨Ø± Ø§Ø±Ø¨Ø¹ Ø·Ø¨Ù‚Ø§Øª Ù…Ø³ØªÙ‚Ù„Ø© Ù…Ù† Ø§Ù„Ù…Ø®Ø§Ø·Ø±.' },
  'Security fact: URL format anomalies are often the fastest phishing clue.': { fr: "Info securite : les anomalies de format URL sont souvent l'indice de phishing le plus rapide.", ar: 'Ù…Ø¹Ù„ÙˆÙ…Ø© Ø§Ù…Ù†ÙŠØ©: ØºØ§Ù„Ø¨Ø§ Ù…Ø§ ØªÙƒÙˆÙ† Ø´Ø°ÙˆØ°Ø§Øª ØµÙŠØºØ© Ø§Ù„Ø±Ø§Ø¨Ø· Ø§Ø³Ø±Ø¹ Ù…Ø¤Ø´Ø± Ø¹Ù„Ù‰ Ø§Ù„ØªØµÙŠØ¯.' },
  'Security fact: Reputation and content signals together reduce false positives.': { fr: "Info securite : combiner reputation et contenu reduit les faux positifs.", ar: 'Ù…Ø¹Ù„ÙˆÙ…Ø© Ø§Ù…Ù†ÙŠØ©: Ø§Ù„Ø¬Ù…Ø¹ Ø¨ÙŠÙ† Ø§Ø´Ø§Ø±Ø§Øª Ø§Ù„Ø³Ù…Ø¹Ø© ÙˆØ§Ù„Ù…Ø­ØªÙˆÙ‰ ÙŠÙ‚Ù„Ù„ Ø§Ù„Ù†ØªØ§Ø¦Ø¬ Ø§Ù„Ø§ÙŠØ¬Ø§Ø¨ÙŠØ© Ø§Ù„ÙƒØ§Ø°Ø¨Ø©.' },
  'Security fact: Layered analysis catches threats single checks miss.': { fr: "Info securite : l'analyse multicouche detecte des menaces que les verifications uniques ratent.", ar: 'Ù…Ø¹Ù„ÙˆÙ…Ø© Ø§Ù…Ù†ÙŠØ©: ÙŠÙƒØ´Ù Ø§Ù„ØªØ­Ù„ÙŠÙ„ Ù…ØªØ¹Ø¯Ø¯ Ø§Ù„Ø·Ø¨Ù‚Ø§Øª ØªÙ‡Ø¯ÙŠØ¯Ø§Øª ØªÙÙˆØªÙ‡Ø§ Ø§Ù„ÙØ­ÙˆØµØ§Øª Ø§Ù„Ù…Ù†ÙØ±Ø¯Ø©.' },
  'This URL matched a known threat feed indicator.': { fr: 'Cette URL correspond a un indicateur connu dans le flux de menaces.', ar: 'Ù‡Ø°Ø§ Ø§Ù„Ø±Ø§Ø¨Ø· Ø·Ø§Ø¨Ù‚ Ù…Ø¤Ø´Ø±Ø§ Ù…Ø¹Ø±ÙˆÙØ§ ÙÙŠ Ù…ØµØ¯Ø± Ø§Ù„ØªÙ‡Ø¯ÙŠØ¯.' },
  'Malicious URLs': { fr: 'URL malveillantes', ar: 'Ø±ÙˆØ§Ø¨Ø· Ø®Ø¨ÙŠØ«Ø©' },
  'Verified URLs': { fr: 'URL verifiees', ar: 'Ø±ÙˆØ§Ø¨Ø· Ù…ÙˆØ«Ù‚Ø©' },
  'Malicious Domains': { fr: 'Domaines malveillants', ar: 'Ù†Ø·Ø§Ù‚Ø§Øª Ø®Ø¨ÙŠØ«Ø©' },
  'Platform Scans': { fr: 'Scans plateforme', ar: 'ÙØ­ÙˆØµØ§Øª Ø§Ù„Ù…Ù†ØµØ©' },
  'Malicious Verdicts': { fr: 'Verdicts malveillants', ar: 'Ø§Ø­ÙƒØ§Ù… Ø®Ø¨ÙŠØ«Ø©' },
  'Search URL': { fr: "Analyser l'URL", ar: 'ÙØ­Øµ Ø§Ù„Ø±Ø§Ø¨Ø·' },
  'Format Validation': { fr: 'Validation du format', ar: 'Ø§Ù„ØªØ­Ù‚Ù‚ Ù…Ù† Ø§Ù„ØµÙŠØºØ©' },
  'Threat Feed Lookup': { fr: 'Recherche dans les flux de menaces', ar: 'Ø§Ù„Ø¨Ø­Ø« ÙÙŠ Ù…ØµØ§Ø¯Ø± Ø§Ù„ØªÙ‡Ø¯ÙŠØ¯' },
  'Domain Reputation': { fr: 'Reputation du domaine', ar: 'Ø³Ù…Ø¹Ø© Ø§Ù„Ù†Ø·Ø§Ù‚' },
  'Content Analysis': { fr: 'Analyse du contenu', ar: 'ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ù…Ø­ØªÙˆÙ‰' },
  'Protocol, syntax, suspicious patterns': { fr: 'Protocole, syntaxe, motifs suspects', ar: 'Ø§Ù„Ø¨Ø±ÙˆØªÙˆÙƒÙˆÙ„ ÙˆØ§Ù„ØµÙŠØ§ØºØ© ÙˆØ§Ù„Ø§Ù†Ù…Ø§Ø· Ø§Ù„Ù…Ø´Ø¨ÙˆÙ‡Ø©' },
  'Known malicious URL/domain match': { fr: 'Correspondance avec URL/domaine malveillant connu', ar: 'Ù…Ø·Ø§Ø¨Ù‚Ø© Ù…Ø¹ Ø±Ø§Ø¨Ø· Ø§Ùˆ Ù†Ø·Ø§Ù‚ Ø®Ø¨ÙŠØ« Ù…Ø¹Ø±ÙˆÙ' },
  'Trust score and domain risk checks': { fr: 'Score de confiance et controles de risque du domaine', ar: 'Ø¯Ø±Ø¬Ø© Ø§Ù„Ø«Ù‚Ø© ÙˆÙØ­ÙˆØµØ§Øª Ù…Ø®Ø§Ø·Ø± Ø§Ù„Ù†Ø·Ø§Ù‚' },
  'Indicators and behavior scoring': { fr: 'Indicateurs et score de comportement', ar: 'Ø§Ù„Ù…Ø¤Ø´Ø±Ø§Øª ÙˆØªÙ‚ÙŠÙŠÙ… Ø§Ù„Ø³Ù„ÙˆÙƒ' },
  'Overall Threat Score': { fr: 'Score global de menace', ar: 'Ø§Ù„Ø¯Ø±Ø¬Ø© Ø§Ù„Ø¹Ø§Ù…Ø© Ù„Ù„ØªÙ‡Ø¯ÙŠØ¯' },
  'Verdict Breakdown': { fr: 'Repartition du verdict', ar: 'ØªÙØµÙŠÙ„ Ø§Ù„Ø­ÙƒÙ…' },
  'Scan Comparison': { fr: 'Comparaison des scans', ar: 'Ù…Ù‚Ø§Ø±Ù†Ø© Ø§Ù„ÙØ­ÙˆØµØ§Øª' },
  'Previous score': { fr: 'Score precedent', ar: 'Ø§Ù„Ù†ØªÙŠØ¬Ø© Ø§Ù„Ø³Ø§Ø¨Ù‚Ø©' },
  Delta: { fr: 'Ecart', ar: 'Ø§Ù„ÙØ±Ù‚' },
  'Overview of your security scans': { fr: 'Vue d ensemble de vos analyses de securite', ar: 'Ù†Ø¸Ø±Ø© Ø¹Ø§Ù…Ø© Ø¹Ù„Ù‰ ÙØ­ÙˆØµØ§ØªÙƒ Ø§Ù„Ø§Ù…Ù†ÙŠØ©' },
  'Auto-refresh every 10s': { fr: 'Actualisation automatique toutes les 10s', ar: 'ØªØ­Ø¯ÙŠØ« ØªÙ„Ù‚Ø§Ø¦ÙŠ ÙƒÙ„ 10 Ø«ÙˆØ§Ù†' },
  'Last update:': { fr: 'Derniere mise a jour :', ar: 'Ø§Ø®Ø± ØªØ­Ø¯ÙŠØ«:' },
  'Waiting...': { fr: 'En attente...', ar: 'ÙÙŠ Ø§Ù„Ø§Ù†ØªØ¸Ø§Ø±...' },
  'Recent Scans': { fr: 'Analyses recentes', ar: 'Ø§Ø­Ø¯Ø« Ø§Ù„ÙØ­ÙˆØµØ§Øª' },
  'Open report': { fr: 'Ouvrir le rapport', ar: 'ÙØªØ­ Ø§Ù„ØªÙ‚Ø±ÙŠØ±' },
  'Loading scans...': { fr: 'Chargement des analyses...', ar: 'Ø¬Ø§Ø± ØªØ­Ù…ÙŠÙ„ Ø§Ù„ÙØ­ÙˆØµØ§Øª...' },
  'No scans yet': { fr: 'Aucune analyse pour le moment', ar: 'Ù„Ø§ ØªÙˆØ¬Ø¯ ÙØ­ÙˆØµØ§Øª Ø¨Ø¹Ø¯' },
  'Total Scans': { fr: 'Total des analyses', ar: 'Ø§Ø¬Ù…Ø§Ù„ÙŠ Ø§Ù„ÙØ­ÙˆØµØ§Øª' },
  'Scan Report': { fr: 'Rapport de scan', ar: 'ØªÙ‚Ø±ÙŠØ± Ø§Ù„ÙØ­Øµ' },
  'Detailed report for scan': { fr: 'Rapport detaille pour le scan', ar: 'ØªÙ‚Ø±ÙŠØ± Ù…ÙØµÙ„ Ù„Ù„ÙØ­Øµ' },
  'Loading full scan report...': { fr: 'Chargement du rapport complet...', ar: 'Ø¬Ø§Ø± ØªØ­Ù…ÙŠÙ„ Ø§Ù„ØªÙ‚Ø±ÙŠØ± Ø§Ù„ÙƒØ§Ù…Ù„...' },
  'URL Scanning': { fr: "Analyse d'URL", ar: 'ÙØ­Øµ Ø§Ù„Ø±ÙˆØ§Ø¨Ø·' },
  'Email Scanning': { fr: 'Analyse email', ar: 'ÙØ­Øµ Ø§Ù„Ø¨Ø±ÙŠØ¯ Ø§Ù„Ø§Ù„ÙƒØªØ±ÙˆÙ†ÙŠ' },
  'File Scanning': { fr: 'Analyse de fichiers', ar: 'ÙØ­Øµ Ø§Ù„Ù…Ù„ÙØ§Øª' },
  'Hash Checking': { fr: 'Verification de hash', ar: 'ÙØ­Øµ Ø§Ù„Ø¨ØµÙ…Ø©' },
  'Gateway Monitoring': { fr: 'Surveillance de la passerelle', ar: 'Ù…Ø±Ø§Ù‚Ø¨Ø© Ø§Ù„Ø¨ÙˆØ§Ø¨Ø©' },
  'Security Scan': { fr: 'Analyse de securite', ar: 'ÙØ­Øµ Ø§Ù…Ù†ÙŠ' },
  'Threat feed match': { fr: 'Correspondance flux de menaces', ar: 'ØªØ·Ø§Ø¨Ù‚ Ù…Ø¹ Ù…ØµØ¯Ø± ØªÙ‡Ø¯ÙŠØ¯Ø§Øª' },
  'Reputation score': { fr: 'Score de reputation', ar: 'Ø¯Ø±Ø¬Ø© Ø§Ù„Ø³Ù…Ø¹Ø©' },
  'Content indicators': { fr: 'Indicateurs de contenu', ar: 'Ù…Ø¤Ø´Ø±Ø§Øª Ø§Ù„Ù…Ø­ØªÙˆÙ‰' },
  'URLs extracted': { fr: 'URL extraites', ar: 'Ø§Ù„Ø±ÙˆØ§Ø¨Ø· Ø§Ù„Ù…Ø³ØªØ®Ø±Ø¬Ø©' },
  Attachments: { fr: 'Pieces jointes', ar: 'Ø§Ù„Ù…Ø±ÙÙ‚Ø§Øª' },
  'Auth failures': { fr: "Echecs d'authentification", ar: 'ÙØ´Ù„ Ø§Ù„ØªØ­Ù‚Ù‚' },
  'Phishing signals': { fr: 'Signaux de phishing', ar: 'Ø§Ø´Ø§Ø±Ø§Øª Ø§Ù„ØªØµÙŠØ¯' },
  Subject: { fr: 'Sujet', ar: 'Ø§Ù„Ù…ÙˆØ¶ÙˆØ¹' },
  Sender: { fr: 'Expediteur', ar: 'Ø§Ù„Ù…Ø±Ø³Ù„' },
  'Hash type': { fr: 'Type de hash', ar: 'Ù†ÙˆØ¹ Ø§Ù„Ø¨ØµÙ…Ø©' },
  Detections: { fr: 'Detections', ar: 'Ø§Ù„Ø§ÙƒØªØ´Ø§ÙØ§Øª' },
  'Database match': { fr: 'Correspondance base de donnees', ar: 'ØªØ·Ø§Ø¨Ù‚ Ù‚Ø§Ø¹Ø¯Ø© Ø§Ù„Ø¨ÙŠØ§Ù†Ø§Øª' },
  'Malware family': { fr: 'Famille malveillante', ar: 'Ø¹Ø§Ø¦Ù„Ø© Ø§Ù„Ø¨Ø±Ù…Ø¬ÙŠØ© Ø§Ù„Ø®Ø¨ÙŠØ«Ø©' },
  'File category': { fr: 'Categorie de fichier', ar: 'ÙØ¦Ø© Ø§Ù„Ù…Ù„Ù' },
  'File size': { fr: 'Taille du fichier', ar: 'Ø­Ø¬Ù… Ø§Ù„Ù…Ù„Ù' },
  Entropy: { fr: 'Entropie', ar: 'Ø§Ù„Ø§Ø¹ØªÙ„Ø§Ø¬' },
  'Threat indicators': { fr: 'Indicateurs de menace', ar: 'Ù…Ø¤Ø´Ø±Ø§Øª Ø§Ù„ØªÙ‡Ø¯ÙŠØ¯' },
  'Code alerts': { fr: 'Alertes de code', ar: 'ØªÙ†Ø¨ÙŠÙ‡Ø§Øª Ø§Ù„ÙƒÙˆØ¯' },
  'No structured detail payload available for this scan.': { fr: 'Aucune charge detaillee structuree pour ce scan.', ar: 'Ù„Ø§ ØªÙˆØ¬Ø¯ Ø¨ÙŠØ§Ù†Ø§Øª ØªÙØµÙŠÙ„ÙŠØ© Ù…Ù†Ø¸Ù…Ø© Ù„Ù‡Ø°Ø§ Ø§Ù„ÙØ­Øµ.' },
  'Email Threat Analysis': { fr: 'Analyse des menaces email', ar: 'ØªØ­Ù„ÙŠÙ„ ØªÙ‡Ø¯ÙŠØ¯Ø§Øª Ø§Ù„Ø¨Ø±ÙŠØ¯' },
  'Header Checks': { fr: 'Verifications des en-tetes', ar: 'ÙØ­ÙˆØµØ§Øª Ø§Ù„ØªØ±ÙˆÙŠØ³Ø©' },
  'Sender Identity': { fr: "Identite de l'expediteur", ar: 'Ù‡ÙˆÙŠØ© Ø§Ù„Ù…Ø±Ø³Ù„' },
  'From, Reply-To, mailed-by, signed-by, auth results': { fr: 'From, Reply-To, mailed-by, signed-by, resultats auth', ar: 'Ù…Ù† ÙˆReply-To Ùˆmailed-by Ùˆsigned-by ÙˆÙ†ØªØ§Ø¦Ø¬ Ø§Ù„ØªØ­Ù‚Ù‚' },
  'URL Reuse': { fr: 'Reutilisation des URL', ar: 'Ø§Ø¹Ø§Ø¯Ø© Ø§Ø³ØªØ®Ø¯Ø§Ù… Ø§Ù„Ø±ÙˆØ§Ø¨Ø·' },
  'Link Extraction': { fr: 'Extraction des liens', ar: 'Ø§Ø³ØªØ®Ø±Ø§Ø¬ Ø§Ù„Ø±ÙˆØ§Ø¨Ø·' },
  'Every extracted link is re-scored by the URL engine': { fr: "Chaque lien extrait est re-evalue par le moteur d'URL", ar: 'ÙƒÙ„ Ø±Ø§Ø¨Ø· Ù…Ø³ØªØ®Ø±Ø¬ ÙŠØ¹Ø§Ø¯ ØªÙ‚ÙŠÙŠÙ…Ù‡ Ø¨ÙˆØ§Ø³Ø·Ø© Ù…Ø­Ø±Ùƒ Ø§Ù„Ø±ÙˆØ§Ø¨Ø·' },
  'Attachment Reuse': { fr: 'Reutilisation des pieces jointes', ar: 'Ø§Ø¹Ø§Ø¯Ø© Ø§Ø³ØªØ®Ø¯Ø§Ù… Ø§Ù„Ù…Ø±ÙÙ‚Ø§Øª' },
  'File Analysis': { fr: 'Analyse de fichier', ar: 'ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ù…Ù„ÙØ§Øª' },
  'Attachments inherit the static file analysis pipeline': { fr: "Les pieces jointes reutilisent la chaine d'analyse statique des fichiers", ar: 'Ø§Ù„Ù…Ø±ÙÙ‚Ø§Øª ØªØ±Ø« Ù…Ø³Ø§Ø± Ø§Ù„ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ø«Ø§Ø¨Øª Ù„Ù„Ù…Ù„ÙØ§Øª' },
  'What This Catches': { fr: 'Ce que cela detecte', ar: 'Ù…Ø§ Ø§Ù„Ø°ÙŠ ÙŠÙƒØªØ´ÙÙ‡ Ù‡Ø°Ø§' },
  '- Sender spoofing and Reply-To mismatch': { fr: "- Usurpation d'expediteur et incoherence Reply-To", ar: '- Ø§Ù†ØªØ­Ø§Ù„ Ø§Ù„Ù…Ø±Ø³Ù„ ÙˆØ¹Ø¯Ù… ØªØ·Ø§Ø¨Ù‚ Reply-To' },
  '- Credential theft and urgency wording': { fr: '- Vol de credentials et formulations urgentes', ar: '- Ø³Ø±Ù‚Ø© Ø¨ÙŠØ§Ù†Ø§Øª Ø§Ù„Ø§Ø¹ØªÙ…Ø§Ø¯ ÙˆØµÙŠØ§ØºØ§Øª Ø§Ù„Ø§Ø³ØªØ¹Ø¬Ø§Ù„' },
  '- Malicious or suspicious extracted URLs': { fr: '- URL extraites malveillantes ou suspectes', ar: '- Ø±ÙˆØ§Ø¨Ø· Ù…Ø³ØªØ®Ø±Ø¬Ø© Ø®Ø¨ÙŠØ«Ø© Ø§Ùˆ Ù…Ø´Ø¨ÙˆÙ‡Ø©' },
  '- Risky attachments such as scripts, archives, or executables': { fr: '- Pieces jointes a risque comme scripts, archives ou executables', ar: '- Ù…Ø±ÙÙ‚Ø§Øª Ø®Ø·Ø±Ø© Ù…Ø«Ù„ Ø§Ù„Ø³ÙƒØ±Ø¨ØªØ§Øª ÙˆØ§Ù„Ø§Ø±Ø´ÙŠÙØ§Øª ÙˆØ§Ù„Ù…Ù„ÙØ§Øª Ø§Ù„ØªÙ†ÙÙŠØ°ÙŠØ©' },
  'Upload .eml Email': { fr: 'Importer un email .eml', ar: 'Ø±ÙØ¹ Ø¨Ø±ÙŠØ¯ .eml' },
  'The scanner now accepts email files only. This preserves headers, MIME structure, body formatting, and attachments.': { fr: "Le scanner accepte maintenant uniquement les fichiers email. Cela preserve les en-tetes, la structure MIME, la mise en forme et les pieces jointes.", ar: 'Ø§Ù„Ù…Ø§Ø³Ø­ ÙŠÙ‚Ø¨Ù„ Ø§Ù„Ø§Ù† Ù…Ù„ÙØ§Øª Ø§Ù„Ø¨Ø±ÙŠØ¯ ÙÙ‚Ø·. Ù‡Ø°Ø§ ÙŠØ­Ø§ÙØ¸ Ø¹Ù„Ù‰ Ø§Ù„ØªØ±ÙˆÙŠØ³Ø§Øª ÙˆØ¨Ù†ÙŠØ© MIME ÙˆØªÙ†Ø³ÙŠÙ‚ Ø§Ù„Ù…Ø­ØªÙˆÙ‰ ÙˆØ§Ù„Ù…Ø±ÙÙ‚Ø§Øª.' },
  'Scanning Email...': { fr: "Analyse de l'email...", ar: 'Ø¬Ø§Ø± ÙØ­Øµ Ø§Ù„Ø¨Ø±ÙŠØ¯...' },
  'Scan Email': { fr: "Analyser l'email", ar: 'ÙØ­Øµ Ø§Ù„Ø¨Ø±ÙŠØ¯' },
  'Email Scan Complete': { fr: "Analyse de l'email terminee", ar: 'Ø§ÙƒØªÙ…Ù„ ÙØ­Øµ Ø§Ù„Ø¨Ø±ÙŠØ¯' },
  'Main audit view (devices moved to dedicated page).': { fr: "Vue d'audit principale (les appareils ont ete deplaces vers une page dediee).", ar: 'ÙˆØ§Ø¬Ù‡Ø© Ø§Ù„ØªØ¯Ù‚ÙŠÙ‚ Ø§Ù„Ø±Ø¦ÙŠØ³ÙŠØ© (ØªÙ… Ù†Ù‚Ù„ Ø§Ù„Ø§Ø¬Ù‡Ø²Ø© Ø§Ù„Ù‰ ØµÙØ­Ø© Ù…Ø®ØµØµØ©).' },
  'Proxy Status': { fr: 'Etat du proxy', ar: 'Ø­Ø§Ù„Ø© Ø§Ù„Ø¨Ø±ÙˆÙƒØ³ÙŠ' },
  Running: { fr: 'En cours', ar: 'Ù‚ÙŠØ¯ Ø§Ù„ØªØ´ØºÙŠÙ„' },
  Stopped: { fr: 'Arrete', ar: 'Ù…ØªÙˆÙ‚Ù' },
  'No data': { fr: 'Aucune donnee', ar: 'Ù„Ø§ ØªÙˆØ¬Ø¯ Ø¨ÙŠØ§Ù†Ø§Øª' },
  'Connected Devices': { fr: 'Appareils connectes', ar: 'Ø§Ù„Ø§Ø¬Ù‡Ø²Ø© Ø§Ù„Ù…ØªØµÙ„Ø©' },
  'Click to open devices page': { fr: 'Cliquez pour ouvrir la page des appareils', ar: 'Ø§Ø¶ØºØ· Ù„ÙØªØ­ ØµÙØ­Ø© Ø§Ù„Ø§Ø¬Ù‡Ø²Ø©' },
  'Block Rate': { fr: 'Taux de blocage', ar: 'Ù…Ø¹Ø¯Ù„ Ø§Ù„Ø­Ø¸Ø±' },
  'Total Events': { fr: 'Total des evenements', ar: 'Ø§Ø¬Ù…Ø§Ù„ÙŠ Ø§Ù„Ø§Ø­Ø¯Ø§Ø«' },
  'All Actions': { fr: 'Toutes les actions', ar: 'ÙƒÙ„ Ø§Ù„Ø§Ø¬Ø±Ø§Ø¡Ø§Øª' },
  'All Verdicts': { fr: 'Tous les verdicts', ar: 'ÙƒÙ„ Ø§Ù„Ø§Ø­ÙƒØ§Ù…' },
  Blocked: { fr: 'Bloque', ar: 'Ù…Ø­Ø¸ÙˆØ±' },
  Allowed: { fr: 'Autorise', ar: 'Ù…Ø³Ù…ÙˆØ­' },
  'Search action, details, user, timestamp': { fr: 'Rechercher action, details, utilisateur, horodatage', ar: 'Ø§Ø¨Ø­Ø« ÙÙŠ Ø§Ù„Ø§Ø¬Ø±Ø§Ø¡ ÙˆØ§Ù„ØªÙØ§ØµÙŠÙ„ ÙˆØ§Ù„Ù…Ø³ØªØ®Ø¯Ù… ÙˆØ§Ù„ÙˆÙ‚Øª' },
  Clear: { fr: 'Effacer', ar: 'Ù…Ø³Ø­' },
  'Loading logs...': { fr: 'Chargement des journaux...', ar: 'Ø¬Ø§Ø± ØªØ­Ù…ÙŠÙ„ Ø§Ù„Ø³Ø¬Ù„Ø§Øª...' },
  Timestamp: { fr: 'Horodatage', ar: 'Ø§Ù„ÙˆÙ‚Øª' },
  Action: { fr: 'Action', ar: 'Ø§Ù„Ø§Ø¬Ø±Ø§Ø¡' },
  Details: { fr: 'Details', ar: 'Ø§Ù„ØªÙØ§ØµÙŠÙ„' },
  Devices: { fr: 'Appareils', ar: 'Ø§Ù„Ø§Ø¬Ù‡Ø²Ø©' },
  'Click a device to show its logs.': { fr: 'Cliquez sur un appareil pour afficher ses journaux.', ar: 'Ø§Ø¶ØºØ· Ø¹Ù„Ù‰ Ø¬Ù‡Ø§Ø² Ù„Ø¹Ø±Ø¶ Ø³Ø¬Ù„Ø§ØªÙ‡.' },
  'Export Device Logs': { fr: "Exporter les journaux de l'appareil", ar: 'ØªØµØ¯ÙŠØ± Ø³Ø¬Ù„Ø§Øª Ø§Ù„Ø¬Ù‡Ø§Ø²' },
  Connected: { fr: 'Connecte', ar: 'Ù…ØªØµÙ„' },
  Disconnected: { fr: 'Deconnecte', ar: 'ØºÙŠØ± Ù…ØªØµÙ„' },
  'Activity online': { fr: 'Activite en ligne', ar: 'Ø§Ù„Ù†Ø´Ø§Ø· Ù…ØªØµÙ„' },
  'Select a device.': { fr: 'Selectionnez un appareil.', ar: 'Ø§Ø®ØªØ± Ø¬Ù‡Ø§Ø²Ø§.' },
  'Search action/details': { fr: 'Rechercher action/details', ar: 'Ø§Ø¨Ø­Ø« ÙÙŠ Ø§Ù„Ø§Ø¬Ø±Ø§Ø¡Ø§Øª/Ø§Ù„ØªÙØ§ØµÙŠÙ„' },
  System: { fr: 'Systeme', ar: 'Ø§Ù„Ù†Ø¸Ø§Ù…' },
  'Design preview for employee web-usage gateway monitoring and policy control.': { fr: "Apercu de design pour la surveillance d'usage web des employes et le controle des politiques.", ar: 'Ù…Ø¹Ø§ÙŠÙ†Ø© ØªØµÙ…ÙŠÙ… Ù„Ù…Ø±Ø§Ù‚Ø¨Ø© Ø§Ø³ØªØ®Ø¯Ø§Ù… Ø§Ù„ÙˆÙŠØ¨ Ù„Ù„Ù…ÙˆØ¸ÙÙŠÙ† ÙˆØ§Ù„ØªØ­ÙƒÙ… ÙÙŠ Ø§Ù„Ø³ÙŠØ§Ø³Ø§Øª.' },
  'UI Mock + Real Scan Flavor': { fr: 'Maquette UI + touche scan reel', ar: 'ÙˆØ§Ø¬Ù‡Ø© ØªØ¬Ø±ÙŠØ¨ÙŠØ© + Ø·Ø§Ø¨Ø¹ ÙØ­Øµ ÙˆØ§Ù‚Ø¹ÙŠ' },
  Overview: { fr: "Vue d'ensemble", ar: 'Ù†Ø¸Ø±Ø© Ø¹Ø§Ù…Ø©' },
  Employees: { fr: 'Employes', ar: 'Ø§Ù„Ù…ÙˆØ¸ÙÙˆÙ†' },
  Policies: { fr: 'Politiques', ar: 'Ø§Ù„Ø³ÙŠØ§Ø³Ø§Øª' },
  'Website activity': { fr: 'Activite web', ar: 'Ù†Ø´Ø§Ø· Ø§Ù„Ù…ÙˆØ§Ù‚Ø¹' },
  'Advanced File Scanner': { fr: 'Analyseur de fichiers avance', ar: 'ÙØ§Ø­Øµ Ø§Ù„Ù…Ù„ÙØ§Øª Ø§Ù„Ù…ØªÙ‚Ø¯Ù…' },
  'Upload a file for layered static and dynamic analysis': { fr: 'Telechargez un fichier pour une analyse statique et dynamique en couches', ar: 'Ø§Ø±ÙØ¹ Ù…Ù„ÙØ§ Ù„ØªØ­Ù„ÙŠÙ„ Ø«Ø§Ø¨Øª ÙˆØ¯ÙŠÙ†Ø§Ù…ÙŠÙƒÙŠ Ù…ØªØ¹Ø¯Ø¯ Ø§Ù„Ø·Ø¨Ù‚Ø§Øª' },
  'Upload File': { fr: 'Televerser un fichier', ar: 'Ø±ÙØ¹ Ù…Ù„Ù' },
  'Security fact: static and dynamic analysis complement each other.': { fr: "Info securite : les analyses statique et dynamique se completent.", ar: 'Ù…Ø¹Ù„ÙˆÙ…Ø© Ø§Ù…Ù†ÙŠØ©: Ø§Ù„ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ø«Ø§Ø¨Øª ÙˆØ§Ù„Ø¯ÙŠÙ†Ø§Ù…ÙŠÙƒÙŠ ÙŠÙƒÙ…Ù„ ÙƒÙ„ Ù…Ù†Ù‡Ù…Ø§ Ø§Ù„Ø§Ø®Ø±.' },
  'Security fact: entropy spikes can reveal packed or obfuscated binaries.': { fr: 'Info securite : des pics d entropie peuvent reveler des binaires compactes ou obfusquees.', ar: 'Ù…Ø¹Ù„ÙˆÙ…Ø© Ø§Ù…Ù†ÙŠØ©: Ù‚Ø¯ ØªÙƒØ´Ù Ù‚Ù…Ù… Ø§Ù„Ø§Ù†ØªØ±ÙˆØ¨ÙŠØ§ Ù…Ù„ÙØ§Øª Ø«Ù†Ø§Ø¦ÙŠØ© Ù…Ø¶ØºÙˆØ·Ø© Ø§Ùˆ Ù…Ù…ÙˆÙ‡Ø©.' },
  'Security fact: dynamic behavior often exposes threats static checks miss.': { fr: 'Info securite : le comportement dynamique revele souvent des menaces ratees par le statique.', ar: 'Ù…Ø¹Ù„ÙˆÙ…Ø© Ø§Ù…Ù†ÙŠØ©: ØºØ§Ù„Ø¨Ø§ Ù…Ø§ ÙŠÙƒØ´Ù Ø§Ù„Ø³Ù„ÙˆÙƒ Ø§Ù„Ø¯ÙŠÙ†Ø§Ù…ÙŠÙƒÙŠ ØªÙ‡Ø¯ÙŠØ¯Ø§Øª ØªÙÙˆØªÙ‡Ø§ Ø§Ù„ÙØ­ÙˆØµØ§Øª Ø§Ù„Ø«Ø§Ø¨ØªØ©.' },
  'Security fact: combining hashes and behavior reduces false positives.': { fr: 'Info securite : combiner les hashes et le comportement reduit les faux positifs.', ar: 'Ù…Ø¹Ù„ÙˆÙ…Ø© Ø§Ù…Ù†ÙŠØ©: Ø¯Ù…Ø¬ Ø§Ù„Ø¨ØµÙ…Ø§Øª Ù…Ø¹ Ø§Ù„Ø³Ù„ÙˆÙƒ ÙŠÙ‚Ù„Ù„ Ø§Ù„Ù†ØªØ§Ø¦Ø¬ Ø§Ù„Ø§ÙŠØ¬Ø§Ø¨ÙŠØ© Ø§Ù„ÙƒØ§Ø°Ø¨Ø©.' },
  'File Analysis Layers': { fr: "Couches d'analyse fichier", ar: 'Ø·Ø¨Ù‚Ø§Øª ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ù…Ù„ÙØ§Øª' },
  '4-layer static analysis + Windows Sandbox dynamic execution': { fr: 'Analyse statique 4 couches + execution dynamique Windows Sandbox', ar: 'ØªØ­Ù„ÙŠÙ„ Ø«Ø§Ø¨Øª Ù…Ù† 4 Ø·Ø¨Ù‚Ø§Øª + ØªÙ†ÙÙŠØ° Ø¯ÙŠÙ†Ø§Ù…ÙŠÙƒÙŠ Ø¹Ø¨Ø± Windows Sandbox' },
  'Layer 1': { fr: 'Couche 1', ar: 'Ø§Ù„Ø·Ø¨Ù‚Ø© 1' },
  'Layer 2': { fr: 'Couche 2', ar: 'Ø§Ù„Ø·Ø¨Ù‚Ø© 2' },
  'Layer 3': { fr: 'Couche 3', ar: 'Ø§Ù„Ø·Ø¨Ù‚Ø© 3' },
  'Layer 4': { fr: 'Couche 4', ar: 'Ø§Ù„Ø·Ø¨Ù‚Ø© 4' },
  'Layer 5': { fr: 'Couche 5', ar: 'Ø§Ù„Ø·Ø¨Ù‚Ø© 5' },
  'File Information': { fr: 'Informations fichier', ar: 'Ù…Ø¹Ù„ÙˆÙ…Ø§Øª Ø§Ù„Ù…Ù„Ù' },
  'Metadata, type classification and entropy': { fr: 'Metadonnees, classification du type et entropie', ar: 'Ø§Ù„Ø¨ÙŠØ§Ù†Ø§Øª Ø§Ù„ÙˆØµÙÙŠØ© ÙˆØªØµÙ†ÙŠÙ Ø§Ù„Ù†ÙˆØ¹ ÙˆØ§Ù„Ø§Ø¹ØªÙ„Ø§Ø¬' },
  'Cryptographic hashes and known-bad database lookup': { fr: 'Hashes cryptographiques et recherche dans une base malveillante connue', ar: 'Ø¨ØµÙ…Ø§Øª ØªØ´ÙÙŠØ±ÙŠØ© ÙˆØ§Ù„Ø¨Ø­Ø« ÙÙŠ Ù‚Ø§Ø¹Ø¯Ø© Ø¨ÙŠØ§Ù†Ø§Øª Ø®Ø¨ÙŠØ«Ø© Ù…Ø¹Ø±ÙˆÙØ©' },
  'Signature and heuristic threat identification': { fr: 'Identification des menaces par signatures et heuristiques', ar: 'ØªØ­Ø¯ÙŠØ¯ Ø§Ù„ØªÙ‡Ø¯ÙŠØ¯Ø§Øª Ø¹Ø¨Ø± Ø§Ù„ØªÙˆØ§Ù‚ÙŠØ¹ ÙˆØ§Ù„Ø§Ø³ØªØ¯Ù„Ø§Ù„Ø§Øª' },
  'Code Analysis': { fr: 'Analyse du code', ar: 'ØªØ­Ù„ÙŠÙ„ Ø§Ù„ÙƒÙˆØ¯' },
  'Suspicious patterns, packer detection and imports': { fr: 'Motifs suspects, detection de packer et imports', ar: 'Ø§Ù†Ù…Ø§Ø· Ù…Ø´Ø¨ÙˆÙ‡Ø© ÙˆØ§ÙƒØªØ´Ø§Ù Ø§Ù„Ø¶ØºØ· ÙˆØ§Ù„Ø§Ø³ØªÙŠØ±Ø§Ø¯Ø§Øª' },
  'Drop your file here or click to browse': { fr: 'Deposez votre fichier ici ou cliquez pour parcourir', ar: 'Ø§Ø³Ø­Ø¨ Ù…Ù„ÙÙƒ Ù‡Ù†Ø§ Ø§Ùˆ Ø§Ø¶ØºØ· Ù„Ù„ØªØµÙØ­' },
  'All file types supported â€¢ Max 100 MB': { fr: 'Tous les types de fichiers sont pris en charge â€¢ 100 Mo max', ar: 'ÙƒÙ„ Ø§Ù†ÙˆØ§Ø¹ Ø§Ù„Ù…Ù„ÙØ§Øª Ù…Ø¯Ø¹ÙˆÙ…Ø© â€¢ Ø§Ù„Ø­Ø¯ Ø§Ù„Ø§Ù‚ØµÙ‰ 100 Ù….Ø¨' },
  'Run another static scan to unlock trend comparison.': { fr: 'Lancez une autre analyse statique pour debloquer la comparaison.', ar: 'Ù‚Ù… Ø¨ØªØ´ØºÙŠÙ„ ÙØ­Øµ Ø«Ø§Ø¨Øª Ø§Ø®Ø± Ù„ÙØªØ­ Ø§Ù„Ù…Ù‚Ø§Ø±Ù†Ø©.' },
  'File Name': { fr: 'Nom du fichier', ar: 'Ø§Ø³Ù… Ø§Ù„Ù…Ù„Ù' },
  Size: { fr: 'Taille', ar: 'Ø§Ù„Ø­Ø¬Ù…' },
  Extension: { fr: 'Extension', ar: 'Ø§Ù„Ø§Ù…ØªØ¯Ø§Ø¯' },
  'Risk Category': { fr: 'Categorie de risque', ar: 'ÙØ¦Ø© Ø§Ù„Ù…Ø®Ø§Ø·Ø±' },
  'High - may be packed/encrypted': { fr: 'Elevee - peut etre compacte/chiffree', ar: 'Ù…Ø±ØªÙØ¹ - Ù‚Ø¯ ÙŠÙƒÙˆÙ† Ù…Ø¶ØºÙˆØ·Ø§ Ø§Ùˆ Ù…Ø´ÙØ±Ø§' },
  'Hash found in malware database': { fr: 'Hash trouve dans la base malveillante', ar: 'ØªÙ… Ø§Ù„Ø¹Ø«ÙˆØ± Ø¹Ù„Ù‰ Ø§Ù„Ø¨ØµÙ…Ø© ÙÙŠ Ù‚Ø§Ø¹Ø¯Ø© Ø§Ù„Ø¨ÙŠØ§Ù†Ø§Øª Ø§Ù„Ø®Ø¨ÙŠØ«Ø©' },
  'Not found in malware database': { fr: 'Aucune correspondance dans la base malveillante', ar: 'Ù„Ù… ÙŠØªÙ… Ø§Ù„Ø¹Ø«ÙˆØ± Ø¹Ù„ÙŠÙ‡Ø§ ÙÙŠ Ù‚Ø§Ø¹Ø¯Ø© Ø§Ù„Ø¨ÙŠØ§Ù†Ø§Øª Ø§Ù„Ø®Ø¨ÙŠØ«Ø©' },
  'Malware Family:': { fr: 'Famille malveillante :', ar: 'Ø¹Ø§Ø¦Ù„Ø© Ø§Ù„Ø¨Ø±Ù…Ø¬ÙŠØ© Ø§Ù„Ø®Ø¨ÙŠØ«Ø©:' },
  'No threats detected': { fr: 'Aucune menace detectee', ar: 'Ù„Ù… ÙŠØªÙ… Ø§ÙƒØªØ´Ø§Ù Ø§ÙŠ ØªÙ‡Ø¯ÙŠØ¯' },
  'Code appears obfuscated': { fr: 'Le code semble obfusque', ar: 'ÙŠØ¨Ø¯Ùˆ Ø§Ù„ÙƒÙˆØ¯ Ù…Ù…ÙˆÙ‡Ø§' },
  'Imported DLLs': { fr: 'DLL importees', ar: 'Ù…ÙƒØªØ¨Ø§Øª DLL Ø§Ù„Ù…Ø³ØªÙˆØ±Ø¯Ø©' },
  'Structural Anomalies': { fr: 'Anomalies structurelles', ar: 'Ø´Ø°ÙˆØ°Ø§Øª Ù‡ÙŠÙƒÙ„ÙŠØ©' },
  'No suspicious code patterns': { fr: 'Aucun motif de code suspect', ar: 'Ù„Ø§ ØªÙˆØ¬Ø¯ Ø§Ù†Ù…Ø§Ø· ÙƒÙˆØ¯ Ù…Ø´Ø¨ÙˆÙ‡Ø©' },
  'Code analysis N/A for': { fr: "Analyse du code non applicable pour", ar: 'ØªØ­Ù„ÙŠÙ„ Ø§Ù„ÙƒÙˆØ¯ ØºÙŠØ± Ù…ØªØ§Ø­ Ù„Ù…Ù„ÙØ§Øª' },
  'Threat detection N/A for': { fr: 'Detection de menace non applicable pour', ar: 'ÙƒØ´Ù Ø§Ù„ØªÙ‡Ø¯ÙŠØ¯ ØºÙŠØ± Ù…ØªØ§Ø­ Ù„Ù…Ù„ÙØ§Øª' },
  files: { fr: 'fichiers', ar: 'Ù…Ù„ÙØ§Øª' },
  executable: { fr: 'executable', ar: 'ØªÙ†ÙÙŠØ°ÙŠ' },
  script: { fr: 'script', ar: 'Ø³ÙƒØ±ÙŠØ¨Øª' },
  archive: { fr: 'archive', ar: 'Ø§Ø±Ø´ÙŠÙ' },
  document: { fr: 'document', ar: 'Ù…Ø³ØªÙ†Ø¯' },
  media: { fr: 'media', ar: 'ÙˆØ³Ø§Ø¦Ø·' },
  unknown: { fr: 'inconnu', ar: 'ØºÙŠØ± Ù…Ø¹Ø±ÙˆÙ' },
  'Static Scan Complete': { fr: 'Analyse statique terminee', ar: 'Ø§ÙƒØªÙ…Ù„ Ø§Ù„ÙØ­Øµ Ø§Ù„Ø«Ø§Ø¨Øª' },
  'Static Score Breakdown': { fr: 'Detail du score statique', ar: 'ØªÙØµÙŠÙ„ Ø§Ù„Ø¯Ø±Ø¬Ø© Ø§Ù„Ø«Ø§Ø¨ØªØ©' },
  'Static Comparison': { fr: 'Comparaison statique', ar: 'Ø§Ù„Ù…Ù‚Ø§Ø±Ù†Ø© Ø§Ù„Ø«Ø§Ø¨ØªØ©' },
  'Run one more scan to unlock comparison insights.': { fr: 'Lancez une autre analyse pour debloquer la comparaison.', ar: 'Ù‚Ù… Ø¨ØªØ´ØºÙŠÙ„ ÙØ­Øµ Ø§Ø®Ø± Ù„ÙØªØ­ Ù…Ø¹Ù„ÙˆÙ…Ø§Øª Ø§Ù„Ù…Ù‚Ø§Ø±Ù†Ø©.' },
  'Running Layer': { fr: 'Execution de la couche', ar: 'ØªØ´ØºÙŠÙ„ Ø§Ù„Ø·Ø¨Ù‚Ø©' },
  'Score contribution': { fr: 'Contribution au score', ar: 'Ø§Ù„Ù…Ø³Ø§Ù‡Ù…Ø© ÙÙŠ Ø§Ù„Ø¯Ø±Ø¬Ø©' },
  'Hash Database': { fr: 'Base de hashes', ar: 'Ù‚Ø§Ø¹Ø¯Ø© Ø¨ÙŠØ§Ù†Ø§Øª Ø§Ù„Ø¨ØµÙ…Ø§Øª' },
  'Entropy Risk': { fr: "Risque d'entropie", ar: 'Ø®Ø·Ø± Ø§Ù„Ø§Ø¹ØªÙ„Ø§Ø¬' },
  'Threat Signatures': { fr: 'Signatures de menace', ar: 'ØªÙˆØ§Ù‚ÙŠØ¹ Ø§Ù„ØªÙ‡Ø¯ÙŠØ¯' },
  'Code Indicators': { fr: 'Indicateurs de code', ar: 'Ù…Ø¤Ø´Ø±Ø§Øª Ø§Ù„ÙƒÙˆØ¯' },
  Format: { fr: 'Format', ar: 'Ø§Ù„ØµÙŠØºØ©' },
  'Threat Feed': { fr: 'Flux de menaces', ar: 'Ù…ØµØ¯Ø± Ø§Ù„ØªÙ‡Ø¯ÙŠØ¯' },
  Reputation: { fr: 'Reputation', ar: 'Ø§Ù„Ø³Ù…Ø¹Ø©' },
  Content: { fr: 'Contenu', ar: 'Ø§Ù„Ù…Ø­ØªÙˆÙ‰' },
  'Suspicious Strings': { fr: 'Chaines suspectes', ar: 'Ø³Ù„Ø§Ø³Ù„ Ù…Ø´Ø¨ÙˆÙ‡Ø©' },
  Packer: { fr: 'Compresseur', ar: 'Ø§Ù„Ø¶Ø§ØºØ·' },
  Cancel: { fr: 'Annuler', ar: 'Ø§Ù„ØºØ§Ø¡' },
  'Cancelling...': { fr: 'Annulation...', ar: 'Ø¬Ø§Ø± Ø§Ù„Ø§Ù„ØºØ§Ø¡...' },
  Normal: { fr: 'Normal', ar: 'Ø·Ø¨ÙŠØ¹ÙŠ' },
  normal: { fr: 'normal', ar: 'Ø·Ø¨ÙŠØ¹ÙŠ' },
  Monitored: { fr: 'Surveille', ar: 'Ù…Ø±Ø§Ù‚Ø¨' },
  Mode: { fr: 'Mode', ar: 'Ø§Ù„ÙˆØ¶Ø¹' },
  ACTIVE: { fr: 'ACTIF', ar: 'Ù†Ø´Ø·' },
  DISABLED: { fr: 'DESACTIVE', ar: 'Ù…Ø¹Ø·Ù„' },
  RISK: { fr: 'RISQUE', ar: 'Ø®Ø·ÙˆØ±Ø©' },
  HIGH: { fr: 'ELEVE', ar: 'Ù…Ø±ØªÙØ¹' },
  MEDIUM: { fr: 'MOYEN', ar: 'Ù…ØªÙˆØ³Ø·' },
  LOW: { fr: 'FAIBLE', ar: 'Ù…Ù†Ø®ÙØ¶' },
  'Dynamic Sandbox Analysis': { fr: 'Analyse dynamique Sandbox', ar: 'ØªØ­Ù„ÙŠÙ„ Ø¯ÙŠÙ†Ø§Ù…ÙŠÙƒÙŠ Ø¯Ø§Ø®Ù„ Sandbox' },
  'Run Dynamic Sandbox Analysis': { fr: "Lancer l'analyse dynamique Sandbox", ar: 'ØªØ´ØºÙŠÙ„ Ø§Ù„ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ø¯ÙŠÙ†Ø§Ù…ÙŠÙƒÙŠ Ø¯Ø§Ø®Ù„ Sandbox' },
  'Process monitoring': { fr: 'Surveillance des processus', ar: 'Ù…Ø±Ø§Ù‚Ø¨Ø© Ø§Ù„Ø¹Ù…Ù„ÙŠØ§Øª' },
  'Network traffic': { fr: 'Trafic reseau', ar: 'Ø­Ø±ÙƒØ© Ø§Ù„Ø´Ø¨ÙƒØ©' },
  'File system': { fr: 'Systeme de fichiers', ar: 'Ù†Ø¸Ø§Ù… Ø§Ù„Ù…Ù„ÙØ§Øª' },
  Registry: { fr: 'Registre', ar: 'Ø§Ù„Ø³Ø¬Ù„' },
  'Run Dynamic URL Scan': { fr: "Lancer l'analyse URL dynamique", ar: 'ØªØ´ØºÙŠÙ„ ÙØ­Øµ Ø§Ù„Ø±Ø§Ø¨Ø· Ø§Ù„Ø¯ÙŠÙ†Ø§Ù…ÙŠÙƒÙŠ' },
  'Layer 5: Dynamic URL Analysis (Sandbox)': { fr: "Couche 5 : analyse URL dynamique (Sandbox)", ar: 'Ø§Ù„Ø·Ø¨Ù‚Ø© 5: ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ø±ÙˆØ§Ø¨Ø· Ø§Ù„Ø¯ÙŠÙ†Ø§Ù…ÙŠÙƒÙŠ (Sandbox)' },
  'Runs only for static clean/suspicious URLs. Local/private targets are blocked.': { fr: 'Fonctionne seulement pour les URL statiques propres/suspectes. Les cibles locales/privees sont bloquees.', ar: 'ÙŠØ¹Ù…Ù„ ÙÙ‚Ø· Ù…Ø¹ Ø§Ù„Ø±ÙˆØ§Ø¨Ø· Ø§Ù„Ù†Ø¸ÙŠÙØ© Ø§Ùˆ Ø§Ù„Ù…Ø´Ø¨ÙˆÙ‡Ø© ÙÙŠ Ø§Ù„ÙØ­Øµ Ø§Ù„Ø«Ø§Ø¨Øª. ÙŠØªÙ… Ø­Ø¸Ø± Ø§Ù„Ø§Ù‡Ø¯Ø§Ù Ø§Ù„Ù…Ø­Ù„ÙŠØ© ÙˆØ§Ù„Ø®Ø§ØµØ©.' },
  'Policy block active: this URL is statically malicious, so sandbox launch is refused.': { fr: "Blocage politique actif : cette URL est statiquement malveillante, le sandbox est refuse.", ar: 'Ø³ÙŠØ§Ø³Ø© Ø§Ù„Ø­Ø¸Ø± Ù…ÙØ¹Ù„Ø©: Ù‡Ø°Ø§ Ø§Ù„Ø±Ø§Ø¨Ø· Ø®Ø¨ÙŠØ« ÙÙŠ Ø§Ù„ÙØ­Øµ Ø§Ù„Ø«Ø§Ø¨Øª Ù„Ø°Ù„Ùƒ ØªÙ… Ø±ÙØ¶ ØªØ´ØºÙŠÙ„ Ø§Ù„Ù€ sandbox.' },
  'Running sandbox URL analysis...': { fr: "Execution de l'analyse URL dans le sandbox...", ar: 'Ø¬Ø§Ø± ØªØ´ØºÙŠÙ„ ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ø±Ø§Ø¨Ø· Ø¯Ø§Ø®Ù„ Ø§Ù„Ù€ sandbox...' },
  Verdict: { fr: 'Verdict', ar: 'Ø§Ù„Ø­ÙƒÙ…' },
  'Dynamic Threat Score': { fr: 'Score de menace dynamique', ar: 'Ø¯Ø±Ø¬Ø© Ø§Ù„ØªÙ‡Ø¯ÙŠØ¯ Ø§Ù„Ø¯ÙŠÙ†Ø§Ù…ÙŠÙƒÙŠ' },
  Duration: { fr: 'Duree', ar: 'Ø§Ù„Ù…Ø¯Ø©' },
  'Observed Connections': { fr: 'Connexions observees', ar: 'Ø§Ù„Ø§ØªØµØ§Ù„Ø§Øª Ø§Ù„Ù…Ø±ØµÙˆØ¯Ø©' },
  'Dynamic Summary': { fr: 'Resume dynamique', ar: 'Ù…Ù„Ø®Øµ Ø¯ÙŠÙ†Ø§Ù…ÙŠÙƒÙŠ' },
  'Top Processes': { fr: 'Ø§Ø¨Ø±Ø² Ø§Ù„Ø¹Ù…Ù„ÙŠØ§Øª', ar: 'Ø§Ù‡Ù… Ø§Ù„Ø¹Ù…Ù„ÙŠØ§Øª' },
  'No notable process activity.': { fr: 'Aucune activite processus notable.', ar: 'Ù„Ø§ ØªÙˆØ¬Ø¯ Ù†Ø´Ø§Ø·Ø§Øª Ø¹Ù…Ù„ÙŠØ§Øª Ù…Ù„Ø­ÙˆØ¸Ø©.' },
  'Top Network Connections': { fr: 'Ø§Ø¨Ø±Ø² Ø§Ù„Ø§ØªØµØ§Ù„Ø§Øª Ø§Ù„Ø´Ø¨ÙƒÙŠØ©', ar: 'Ø§Ù‡Ù… Ø§ØªØµØ§Ù„Ø§Øª Ø§Ù„Ø´Ø¨ÙƒØ©' },
  'No external network telemetry captured.': { fr: 'Aucune telemetrie reseau externe capturee.', ar: 'Ù„Ù… ÙŠØªÙ… Ø§Ù„ØªÙ‚Ø§Ø· Ù‚ÙŠØ§Ø³Ø§Øª Ø´Ø¨ÙƒØ© Ø®Ø§Ø±Ø¬ÙŠØ©.' },
  'URL structure and syntax analysis': { fr: 'Analyse de la structure et de la syntaxe URL', ar: 'ØªØ­Ù„ÙŠÙ„ Ø¨Ù†ÙŠØ© Ø§Ù„Ø±Ø§Ø¨Ø· ÙˆØµÙŠØºØªÙ‡' },
  'Issues Detected:': { fr: 'Problemes detectes :', ar: 'Ø§Ù„Ù…Ø´Ø§ÙƒÙ„ Ø§Ù„Ù…ÙƒØªØ´ÙØ©:' },
  'No format issues detected': { fr: 'Aucun probleme de format detecte', ar: 'Ù„Ù… ÙŠØªÙ… Ø§ÙƒØªØ´Ø§Ù Ù…Ø´Ø§ÙƒÙ„ ÙÙŠ Ø§Ù„ØµÙŠØºØ©' },
  'Threat Feed Database': { fr: 'Base de flux de menaces', ar: 'Ù‚Ø§Ø¹Ø¯Ø© Ø¨ÙŠØ§Ù†Ø§Øª Ù…ØµØ§Ø¯Ø± Ø§Ù„ØªÙ‡Ø¯ÙŠØ¯' },
  'Known malicious URL and domain lookup': { fr: "Recherche d'URL et domaines malveillants connus", ar: 'Ø§Ù„Ø¨Ø­Ø« Ø¹Ù† Ø±ÙˆØ§Ø¨Ø· ÙˆÙ†Ø·Ø§Ù‚Ø§Øª Ø®Ø¨ÙŠØ«Ø© Ù…Ø¹Ø±ÙˆÙØ©' },
  'Not Found in Database': { fr: 'Non trouve dans la base', ar: 'Ù„Ù… ÙŠØªÙ… Ø§Ù„Ø¹Ø«ÙˆØ± Ø¹Ù„ÙŠÙ‡ ÙÙŠ Ù‚Ø§Ø¹Ø¯Ø© Ø§Ù„Ø¨ÙŠØ§Ù†Ø§Øª' },
  Source: { fr: 'Source', ar: 'Ø§Ù„Ù…ØµØ¯Ø±' },
  'No additional info': { fr: 'Aucune information supplementaire', ar: 'Ù„Ø§ ØªÙˆØ¬Ø¯ Ù…Ø¹Ù„ÙˆÙ…Ø§Øª Ø§Ø¶Ø§ÙÙŠØ©' },
  'Domain matches:': { fr: 'Correspondances domaine :', ar: 'ØªØ·Ø§Ø¨Ù‚Ø§Øª Ø§Ù„Ù†Ø·Ø§Ù‚:' },
  'No Layer 2 data returned.': { fr: 'Aucune donnee retournee pour la couche 2.', ar: 'Ù„Ù… ÙŠØªÙ… Ø§Ø±Ø¬Ø§Ø¹ Ø¨ÙŠØ§Ù†Ø§Øª Ù„Ù„Ø·Ø¨Ù‚Ø© 2.' },
  'Domain trust and reputation analysis': { fr: 'Analyse de confiance et de reputation du domaine', ar: 'ØªØ­Ù„ÙŠÙ„ Ø«Ù‚Ø© ÙˆØ³Ù…Ø¹Ø© Ø§Ù„Ù†Ø·Ø§Ù‚' },
  'Reputation Score': { fr: 'Score de reputation', ar: 'Ø¯Ø±Ø¬Ø© Ø§Ù„Ø³Ù…Ø¹Ø©' },
  'Reputation Issues:': { fr: 'Problemes de reputation :', ar: 'Ù…Ø´Ø§ÙƒÙ„ Ø§Ù„Ø³Ù…Ø¹Ø©:' },
  'No reputation issues detected': { fr: 'Aucun probleme de reputation detecte', ar: 'Ù„Ù… ÙŠØªÙ… Ø§ÙƒØªØ´Ø§Ù Ù…Ø´Ø§ÙƒÙ„ Ø³Ù…Ø¹Ø©' },
  'No Layer 3 data returned.': { fr: 'Aucune donnee retournee pour la couche 3.', ar: 'Ù„Ù… ÙŠØªÙ… Ø§Ø±Ø¬Ø§Ø¹ Ø¨ÙŠØ§Ù†Ø§Øª Ù„Ù„Ø·Ø¨Ù‚Ø© 3.' },
  'Behavioral and content indicators': { fr: 'Indicateurs comportementaux et de contenu', ar: 'Ù…Ø¤Ø´Ø±Ø§Øª Ø³Ù„ÙˆÙƒÙŠØ© ÙˆÙ…Ø¤Ø´Ø±Ø§Øª Ù…Ø­ØªÙˆÙ‰' },
  'Indicators Found:': { fr: 'Indicateurs trouves :', ar: 'Ø§Ù„Ù…Ø¤Ø´Ø±Ø§Øª Ø§Ù„Ù…ÙˆØ¬ÙˆØ¯Ø©:' },
  'No suspicious content indicators': { fr: 'Aucun indicateur de contenu suspect', ar: 'Ù„Ø§ ØªÙˆØ¬Ø¯ Ù…Ø¤Ø´Ø±Ø§Øª Ù…Ø­ØªÙˆÙ‰ Ù…Ø´Ø¨ÙˆÙ‡Ø©' },
  'Content threat score': { fr: 'Score de menace du contenu', ar: 'Ø¯Ø±Ø¬Ø© ØªÙ‡Ø¯ÙŠØ¯ Ø§Ù„Ù…Ø­ØªÙˆÙ‰' },
  'No Layer 4 data returned.': { fr: 'Aucune donnee retournee pour la couche 4.', ar: 'Ù„Ù… ÙŠØªÙ… Ø§Ø±Ø¬Ø§Ø¹ Ø¨ÙŠØ§Ù†Ø§Øª Ù„Ù„Ø·Ø¨Ù‚Ø© 4.' },
  'Active Gateways': { fr: 'Passerelles actives', ar: 'Ø§Ù„Ø¨ÙˆØ§Ø¨Ø§Øª Ø§Ù„Ù†Ø´Ø·Ø©' },
  'Tracked Searches': { fr: 'Recherches suivies', ar: 'Ø¹Ù…Ù„ÙŠØ§Øª Ø§Ù„Ø¨Ø­Ø« Ø§Ù„Ù…ØªØªØ¨Ø¹Ø©' },
  'Policy Hits': { fr: 'Declenchements de politiques', ar: 'Ø¶Ø±Ø¨Ø§Øª Ø§Ù„Ø³ÙŠØ§Ø³Ø§Øª' },
  'High-Risk Users': { fr: 'Utilisateurs a haut risque', ar: 'Ù…Ø³ØªØ®Ø¯Ù…ÙˆÙ† Ø¹Ø§Ù„ÙŠ Ø§Ù„Ø®Ø·ÙˆØ±Ø©' },
  'Employee Search Distribution': { fr: 'Repartition des recherches employees', ar: 'ØªÙˆØ²ÙŠØ¹ Ø¨Ø­Ø« Ø§Ù„Ù…ÙˆØ¸ÙÙŠÙ†' },
  'Employee Behavior Breakdown': { fr: 'Repartition du comportement des employes', ar: 'ØªÙØµÙŠÙ„ Ø³Ù„ÙˆÙƒ Ø§Ù„Ù…ÙˆØ¸ÙÙŠÙ†' },
  'Policy Builder Preview': { fr: 'Apercu du constructeur de politiques', ar: 'Ù…Ø¹Ø§ÙŠÙ†Ø© Ù…Ù†Ø´Ø¦ Ø§Ù„Ø³ÙŠØ§Ø³Ø§Øª' },
  'Top websites from URL scan data': { fr: "Principaux sites a partir des donnees d'analyse URL", ar: 'Ø§Ø¨Ø±Ø² Ø§Ù„Ù…ÙˆØ§Ù‚Ø¹ Ù…Ù† Ø¨ÙŠØ§Ù†Ø§Øª ÙØ­Øµ Ø§Ù„Ø±ÙˆØ§Ø¨Ø·' },
  'tracked hits': { fr: 'hits suivis', ar: 'Ø§Ù„Ø²ÙŠØ§Ø±Ø§Øª Ø§Ù„Ù…ØªØªØ¨Ø¹Ø©' },
  searches: { fr: 'recherches', ar: 'Ø¹Ù…Ù„ÙŠØ§Øª Ø¨Ø­Ø«' },
  'Non-work trend:': { fr: 'Tendance hors travail :', ar: 'Ø§ØªØ¬Ø§Ù‡ ØºÙŠØ± Ù…Ù‡Ù†ÙŠ:' },
  'matches this week': { fr: 'correspondances cette semaine', ar: 'Ù…Ø·Ø§Ø¨Ù‚Ø§Øª Ù‡Ø°Ø§ Ø§Ù„Ø§Ø³Ø¨ÙˆØ¹' },
  'Gateway Device Status': { fr: 'Etat des appareils de la passerelle', ar: 'Ø­Ø§Ù„Ø© Ø§Ø¬Ù‡Ø²Ø© Ø§Ù„Ø¨ÙˆØ§Ø¨Ø©' },
  'Real-time': { fr: 'Temps reel', ar: 'Ø§Ù„ÙˆÙ‚Øª Ø§Ù„Ø­Ù‚ÙŠÙ‚ÙŠ' },
  'Gateway Health Index': { fr: 'Indice de sante de la passerelle', ar: 'Ù…Ø¤Ø´Ø± ØµØ­Ø© Ø§Ù„Ø¨ÙˆØ§Ø¨Ø©' },
  'endpoints operational': { fr: 'terminaux operationnels', ar: 'Ù†Ù‚Ø§Ø· Ù†Ù‡Ø§ÙŠØ© Ø¹Ø§Ù…Ù„Ø©' },
  Online: { fr: 'En ligne', ar: 'Ù…ØªØµÙ„' },
  Warning: { fr: 'Alerte', ar: 'ØªØ­Ø°ÙŠØ±' },
  Offline: { fr: 'Hors ligne', ar: 'ØºÙŠØ± Ù…ØªØµÙ„' },
  'last sync': { fr: 'derniere synchro', ar: 'Ø§Ø®Ø± Ù…Ø²Ø§Ù…Ù†Ø©' },
  'Live Traffic Snapshot': { fr: 'Apercu du trafic en direct', ar: 'Ù„Ù‚Ø·Ø© Ù„Ø­Ø±ÙƒØ© Ø§Ù„Ù…Ø±ÙˆØ± Ø§Ù„Ù…Ø¨Ø§Ø´Ø±Ø©' },
  'recent events': { fr: 'evenements recents', ar: 'Ø§Ø­Ø¯Ø§Ø« Ø­Ø¯ÙŠØ«Ø©' },
  'Choose file': { fr: 'Choisir un fichier', ar: 'Ø§Ø®ØªØ± Ù…Ù„ÙØ§' },
  'Static Analysis': { fr: 'Analyse statique', ar: 'Ø§Ù„ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ø«Ø§Ø¨Øª' },
  'Dynamic Analysis': { fr: 'Analyse dynamique', ar: 'Ø§Ù„ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ø¯ÙŠÙ†Ø§Ù…ÙŠÙƒÙŠ' },
  'Analysis Report': { fr: "Rapport d'analyse", ar: 'ØªÙ‚Ø±ÙŠØ± Ø§Ù„ØªØ­Ù„ÙŠÙ„' },
  'Session expired. Please sign in again.': { fr: 'Session expiree. Veuillez vous reconnecter.', ar: 'Ø§Ù†ØªÙ‡Øª Ø§Ù„Ø¬Ù„Ø³Ø©. ÙŠØ±Ø¬Ù‰ ØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ø¯Ø®ÙˆÙ„ Ù…Ø±Ø© Ø§Ø®Ø±Ù‰.' },
  'An error occurred': { fr: 'Une erreur est survenue', ar: 'Ø­Ø¯Ø« Ø®Ø·Ø§' },
  'Failed to fetch logs': { fr: 'Impossible de recuperer les journaux', ar: 'ÙØ´Ù„ ÙÙŠ Ø¬Ù„Ø¨ Ø§Ù„Ø³Ø¬Ù„Ø§Øª' },
  'Failed to fetch audit logs': { fr: "Impossible de recuperer les journaux d'audit", ar: 'ÙØ´Ù„ ÙÙŠ Ø¬Ù„Ø¨ Ø³Ø¬Ù„Ø§Øª Ø§Ù„ØªØ¯Ù‚ÙŠÙ‚' },
  'Failed to fetch gateway telemetry': { fr: 'Impossible de recuperer la telemetrie de la passerelle', ar: 'ÙØ´Ù„ ÙÙŠ Ø¬Ù„Ø¨ Ù‚ÙŠØ§Ø³Ø§Øª Ø§Ù„Ø¨ÙˆØ§Ø¨Ø©' },
  'Failed to load blocklist': { fr: 'Impossible de charger la blocklist', ar: 'ÙØ´Ù„ ÙÙŠ ØªØ­Ù…ÙŠÙ„ Ù‚Ø§Ø¦Ù…Ø© Ø§Ù„Ø­Ø¸Ø±' },
  'Please enter a valid domain or URL': { fr: 'Veuillez saisir un domaine ou une URL valide', ar: 'ÙŠØ±Ø¬Ù‰ Ø§Ø¯Ø®Ø§Ù„ Ù†Ø·Ø§Ù‚ Ø§Ùˆ Ø±Ø§Ø¨Ø· ØµØ§Ù„Ø­' },
  'Failed to add block rule': { fr: "Echec de l'ajout de la regle de blocage", ar: 'ÙØ´Ù„ ÙÙŠ Ø§Ø¶Ø§ÙØ© Ù‚Ø§Ø¹Ø¯Ø© Ø§Ù„Ø­Ø¸Ø±' },
  'Failed to update rule': { fr: 'Echec de la mise a jour de la regle', ar: 'ÙØ´Ù„ ÙÙŠ ØªØ­Ø¯ÙŠØ« Ø§Ù„Ù‚Ø§Ø¹Ø¯Ø©' },
  'Failed to remove rule': { fr: 'Echec de la suppression de la regle', ar: 'ÙØ´Ù„ ÙÙŠ Ø­Ø°Ù Ø§Ù„Ù‚Ø§Ø¹Ø¯Ø©' },
  'You must be signed in.': { fr: 'Vous devez etre connecte.', ar: 'ÙŠØ¬Ø¨ Ø§Ù† ØªÙƒÙˆÙ† Ù…Ø³Ø¬Ù„ Ø§Ù„Ø¯Ø®ÙˆÙ„.' },
  'Upload an .eml email file to continue.': { fr: 'Telechargez un fichier email .eml pour continuer.', ar: 'Ù‚Ù… Ø¨Ø±ÙØ¹ Ù…Ù„Ù Ø¨Ø±ÙŠØ¯ .eml Ù„Ù„Ù…ØªØ§Ø¨Ø¹Ø©.' },
  'Email scan failed': { fr: "Echec de l'analyse email", ar: 'ÙØ´Ù„ ÙØ­Øµ Ø§Ù„Ø¨Ø±ÙŠØ¯' },
  'Please login and enter a valid URL': { fr: 'Veuillez vous connecter et saisir une URL valide', ar: 'ÙŠØ±Ø¬Ù‰ ØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ø¯Ø®ÙˆÙ„ ÙˆØ§Ø¯Ø®Ø§Ù„ Ø±Ø§Ø¨Ø· ØµØ§Ù„Ø­' },
  'Scan failed': { fr: "Echec de l'analyse", ar: 'ÙØ´Ù„ Ø§Ù„ÙØ­Øµ' },
  'Run static scan first, then start dynamic analysis.': { fr: "Lancez d'abord l'analyse statique puis l'analyse dynamique.", ar: 'Ù‚Ù… Ø¨ØªØ´ØºÙŠÙ„ Ø§Ù„ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ø«Ø§Ø¨Øª Ø§ÙˆÙ„Ø§ Ø«Ù… Ø§Ø¨Ø¯Ø£ Ø§Ù„ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ø¯ÙŠÙ†Ø§Ù…ÙŠÙƒÙŠ.' },
  'Dynamic URL analysis blocked by policy: static verdict is malicious.': { fr: "Analyse URL dynamique bloquee par la politique : le verdict statique est malveillant.", ar: 'ØªÙ… Ø­Ø¸Ø± ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ø±Ø§Ø¨Ø· Ø§Ù„Ø¯ÙŠÙ†Ø§Ù…ÙŠÙƒÙŠ Ø¨Ø³Ø¨Ø¨ Ø§Ù„Ø³ÙŠØ§Ø³Ø©: Ø§Ù„Ø­ÙƒÙ… Ø§Ù„Ø«Ø§Ø¨Øª Ø®Ø¨ÙŠØ«.' },
  'Preparing URL sandbox environment...': { fr: "Preparation de l'environnement sandbox URL...", ar: 'Ø¬Ø§Ø± ØªØ¬Ù‡ÙŠØ² Ø¨ÙŠØ¦Ø© Ø¹Ø²Ù„ Ø§Ù„Ø±Ø§Ø¨Ø·...' },
  'Failed to start dynamic URL analysis.': { fr: "Impossible de demarrer l'analyse URL dynamique.", ar: 'ÙØ´Ù„ Ø¨Ø¯Ø¡ ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ø±Ø§Ø¨Ø· Ø§Ù„Ø¯ÙŠÙ†Ø§Ù…ÙŠÙƒÙŠ.' },
  'Dynamic URL analysis failed.': { fr: "L'analyse URL dynamique a echoue.", ar: 'ÙØ´Ù„ ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ø±Ø§Ø¨Ø· Ø§Ù„Ø¯ÙŠÙ†Ø§Ù…ÙŠÙƒÙŠ.' },
};

const arabicLiteralOverrides: Record<string, string> = {
  Parameters: 'الإعدادات',
  'Manage your language, appearance, account, and session from one place.': 'إدارة اللغة والمظهر والحساب والجلسة من مكان واحد.',
  'Language Settings': 'إعدادات اللغة',
  'Choose the interface language.': 'اختر لغة الواجهة.',
  'Appearance Settings': 'إعدادات المظهر',
  'Switch between light and dark mode.': 'التبديل بين الوضع الفاتح والداكن.',
  'Account Settings': 'إعدادات الحساب',
  'Review your current account information.': 'مراجعة معلومات الحساب الحالي.',
  Logout: 'تسجيل الخروج',
  'End the current session securely.': 'إنهاء الجلسة الحالية بأمان.',
  'Select the language used across the SECA interface.': 'اختر اللغة المستخدمة في واجهة SECA.',
  'Choose how the platform should look on this device.': 'اختر مظهر المنصة على هذا الجهاز.',
  'Use a brighter interface.': 'استخدام واجهة أكثر سطوعا.',
  'Use a darker interface.': 'استخدام واجهة داكنة.',
  'Current account information for the active session.': 'معلومات الحساب للجلسة النشطة.',
  Dashboard: 'لوحة التحكم',
  'File Scanner': 'فاحص الملفات',
  'URL Scanner': 'فاحص الروابط',
  'Email Scanner': 'فاحص البريد الإلكتروني',
  'Hash Checker': 'فاحص البصمة',
  Monitoring: 'المراقبة',
  'Audit Logs': 'سجلات التدقيق',
  'Access Control': 'التحكم في الوصول',
  Policies: 'السياسات',
  'Security Analyzer': 'محلل الأمان',
  Admin: 'مسؤول',
  User: 'مستخدم',
  'Light Mode': 'الوضع الفاتح',
  'Dark Mode': 'الوضع الداكن',
  'Website Access Control': 'التحكم في الوصول إلى المواقع',
  'Advanced URL Scanner': 'فاحص الروابط المتقدم',
  'Advanced File Scanner': 'فاحص الملفات المتقدم',
  English: 'الإنجليزية',
  Francais: 'الفرنسية',
  Arabic: 'العربية',
};

const arabicKeyOverrides: Record<string, string> = {
  'settings.button': 'الإعدادات',
  'settings.title': 'الإعدادات',
  'settings.subtitle': 'اختر لغة الواجهة.',
  'settings.language': 'اللغة',
  'settings.appearance': 'المظهر',
  'settings.account': 'الحساب',
  'settings.logout': 'تسجيل الخروج',
  'settings.close': 'إغلاق',
  'language.ar': 'العربية',
  'language.fr': 'الفرنسية',
  'language.en': 'الإنجليزية',
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
        : `ØªÙ†ØªÙ‡ÙŠ ØµÙ„Ø§Ø­ÙŠØ© Ø§Ù„Ø±Ù…Ø² Ø®Ù„Ø§Ù„ ${match[1]} Ø¯Ù‚ÙŠÙ‚Ø© ÙˆÙŠÙ…ÙƒÙ† Ø§Ø¹Ø§Ø¯Ø© Ø§Ø±Ø³Ø§Ù„Ù‡ Ø¨Ø¹Ø¯ ${match[2]}Ø«.`,
  },
  {
    pattern: /^Code expires in (\d+) minutes\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `Le code expire dans ${match[1]} minutes.`
        : `ØªÙ†ØªÙ‡ÙŠ ØµÙ„Ø§Ø­ÙŠØ© Ø§Ù„Ø±Ù…Ø² Ø®Ù„Ø§Ù„ ${match[1]} Ø¯Ù‚ÙŠÙ‚Ø©.`,
  },
  {
    pattern: /^Dev OTP: (\d+)$/,
    render: (match, language) =>
      language === 'fr'
        ? `OTP dev : ${match[1]}`
        : `Ø±Ù…Ø² Ø§Ù„ØªØ·ÙˆÙŠØ±: ${match[1]}`,
  },
  {
    pattern: /^Offline > (\d+)s$/,
    render: (match, language) =>
      language === 'fr'
        ? `Hors ligne > ${match[1]}s`
        : `ØºÙŠØ± Ù…ØªØµÙ„ > ${match[1]}Ø«`,
  },
  {
    pattern: /^Active <= (\d+)s$/,
    render: (match, language) =>
      language === 'fr'
        ? `Actif <= ${match[1]}s`
        : `Ù†Ø´Ø· <= ${match[1]}Ø«`,
  },
  {
    pattern: /^Offline after (\d+)s idle$/,
    render: (match, language) =>
      language === 'fr'
        ? `Hors ligne apres ${match[1]}s d'inactivite`
        : `ØºÙŠØ± Ù…ØªØµÙ„ Ø¨Ø¹Ø¯ ${match[1]}Ø« Ù…Ù† Ø§Ù„Ø®Ù…ÙˆÙ„`,
  },
  {
    pattern: /^Last activity: (.+) ago$/,
    render: (match, language) =>
      language === 'fr'
        ? `Derniere activite : il y a ${match[1]}`
        : `Ø§Ø®Ø± Ù†Ø´Ø§Ø·: Ù…Ù†Ø° ${match[1]}`,
  },
  {
    pattern: /^Last seen: (.+)$/,
    render: (match, language) =>
      language === 'fr'
        ? `Derniere apparition : ${match[1]}`
        : `Ø§Ø®Ø± Ø¸Ù‡ÙˆØ±: ${match[1]}`,
  },
  {
    pattern: /^User #(\d+)$/,
    render: (match, language) =>
      language === 'fr'
        ? `Utilisateur #${match[1]}`
        : `Ø§Ù„Ù…Ø³ØªØ®Ø¯Ù… #${match[1]}`,
  },
  {
    pattern: /^Invalid (MD5|SHA1|SHA256) hash format\. Expected (\d+) hexadecimal characters\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `Format de hash ${match[1]} invalide. ${match[2]} caracteres hexadecimaux attendus.`
        : `ØªÙ†Ø³ÙŠÙ‚ Ø¨ØµÙ…Ø© ${match[1]} ØºÙŠØ± ØµØ§Ù„Ø­. Ø§Ù„Ù…ØªÙˆÙ‚Ø¹ ${match[2]} Ù…Ø­Ø±ÙØ§ Ø³Ø¯Ø§Ø³ÙŠØ§ Ø¹Ø´Ø±ÙŠØ§.`,
  },
  {
    pattern: /^(\d+) out of (\d+) engines flagged this file\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `${match[1]} moteurs sur ${match[2]} ont signale ce fichier.`
        : `ØªÙ… ÙˆØ¶Ø¹ Ø¹Ù„Ø§Ù…Ø© Ø¹Ù„Ù‰ Ù‡Ø°Ø§ Ø§Ù„Ù…Ù„Ù Ø¨ÙˆØ§Ø³Ø·Ø© ${match[1]} Ù…Ù† Ø§ØµÙ„ ${match[2]} Ù…Ø­Ø±ÙƒØ§Øª.`,
  },
  {
    pattern: /^Threat feed currently tracks ([\d.,\s]+) malicious URLs\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `Le flux de menaces suit actuellement ${match[1]} URL malveillantes.`
        : `ÙŠØªØªØ¨Ø¹ Ù…ØµØ¯Ø± Ø§Ù„ØªÙ‡Ø¯ÙŠØ¯ Ø­Ø§Ù„ÙŠØ§ ${match[1]} Ø±Ø§Ø¨Ø·Ø§ Ø®Ø¨ÙŠØ«Ø§.`,
  },
  {
    pattern: /^([\d.,\s]+) unique malicious domains are indexed in your feed\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `${match[1]} domaines malveillants uniques sont indexes dans votre flux.`
        : `ÙŠÙˆØ¬Ø¯ ${match[1]} Ù†Ø·Ø§Ù‚Ø§ Ø®Ø¨ÙŠØ«Ø§ ÙØ±ÙŠØ¯Ø§ Ù…ÙÙ‡Ø±Ø³Ø§ ÙÙŠ Ù…ØµØ¯Ø± Ø§Ù„ØªÙ‡Ø¯ÙŠØ¯ Ù„Ø¯ÙŠÙƒ.`,
  },
  {
    pattern: /^([\d.,\s]+) URL\/file scans are logged in your platform\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `${match[1]} scans URL/fichier sont journalises sur votre plateforme.`
        : `ØªÙ… ØªØ³Ø¬ÙŠÙ„ ${match[1]} Ù…Ù† ÙØ­ÙˆØµØ§Øª Ø§Ù„Ø±ÙˆØ§Ø¨Ø·/Ø§Ù„Ù…Ù„ÙØ§Øª ÙÙŠ Ù…Ù†ØµØªÙƒ.`,
  },
  {
    pattern: /^([\d.,\s]+) historical scans were marked malicious\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `${match[1]} scans historiques ont ete marques malveillants.`
        : `ØªÙ… ØªÙ…ÙŠÙŠØ² ${match[1]} Ù…Ù† Ø§Ù„ÙØ­ÙˆØµØ§Øª Ø§Ù„Ø³Ø§Ø¨Ù‚Ø© Ø¹Ù„Ù‰ Ø§Ù†Ù‡Ø§ Ø®Ø¨ÙŠØ«Ø©.`,
  },
  {
    pattern: /^([\d.,\s]+) historical scans were marked suspicious\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `${match[1]} scans historiques ont ete marques suspects.`
        : `ØªÙ… ØªÙ…ÙŠÙŠØ² ${match[1]} Ù…Ù† Ø§Ù„ÙØ­ÙˆØµØ§Øª Ø§Ù„Ø³Ø§Ø¨Ù‚Ø© Ø¹Ù„Ù‰ Ø§Ù†Ù‡Ø§ Ù…Ø´Ø¨ÙˆÙ‡Ø©.`,
  },
  {
    pattern: /^([\d.,\s]+) total security scans are logged in your platform\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `${match[1]} scans de securite au total sont journalises sur votre plateforme.`
        : `ØªÙ… ØªØ³Ø¬ÙŠÙ„ ${match[1]} Ù…Ù† ÙØ­ÙˆØµØ§Øª Ø§Ù„Ø§Ù…Ù† Ø§Ù„Ø§Ø¬Ù…Ø§Ù„ÙŠØ© ÙÙŠ Ù…Ù†ØµØªÙƒ.`,
  },
  {
    pattern: /^([\d.,\s]+) historical scans were flagged malicious\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `${match[1]} scans historiques ont ete signales malveillants.`
        : `ØªÙ… Ø§Ù„Ø§Ø¨Ù„Ø§Øº Ø¹Ù† ${match[1]} Ù…Ù† Ø§Ù„ÙØ­ÙˆØµØ§Øª Ø§Ù„Ø³Ø§Ø¨Ù‚Ø© ÙƒØ®Ø¨ÙŠØ«Ø©.`,
  },
  {
    pattern: /^([\d.,\s]+) scans were marked suspicious and need triage\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `${match[1]} scans ont ete marques suspects et necessitent un triage.`
        : `ØªÙ… ØªÙ…ÙŠÙŠØ² ${match[1]} Ù…Ù† Ø§Ù„ÙØ­ÙˆØµØ§Øª Ø¹Ù„Ù‰ Ø§Ù†Ù‡Ø§ Ù…Ø´Ø¨ÙˆÙ‡Ø© ÙˆØªØ­ØªØ§Ø¬ Ø§Ù„Ù‰ ÙØ±Ø².`,
  },
  {
    pattern: /^Latest URL risk score: (\d+)\/100\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `Dernier score de risque URL : ${match[1]}/100.`
        : `Ø§Ø®Ø± Ø¯Ø±Ø¬Ø© Ù…Ø®Ø§Ø·Ø±Ø© Ù„Ù„Ø±Ø§Ø¨Ø·: ${match[1]}/100.`,
  },
  {
    pattern: /^Latest static score: (\d+)\/100\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `Dernier score statique : ${match[1]}/100.`
        : `Ø§Ø®Ø± Ø¯Ø±Ø¬Ø© Ø«Ø§Ø¨ØªØ©: ${match[1]}/100.`,
  },
  {
    pattern: /^Static analysis identified (\d+) threat indicators\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `L'analyse statique a identifie ${match[1]} indicateurs de menace.`
        : `Ø­Ø¯Ø¯ Ø§Ù„ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ø«Ø§Ø¨Øª ${match[1]} Ù…Ø¤Ø´Ø±Ø§Øª ØªÙ‡Ø¯ÙŠØ¯.`,
  },
  {
    pattern: /^Latest dynamic score: (\d+)\/100 after (\d+)s of execution\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `Dernier score dynamique : ${match[1]}/100 apres ${match[2]}s d'execution.`
        : `Ø§Ø®Ø± Ø¯Ø±Ø¬Ø© Ø¯ÙŠÙ†Ø§Ù…ÙŠÙƒÙŠØ©: ${match[1]}/100 Ø¨Ø¹Ø¯ ${match[2]} Ø«Ø§Ù†ÙŠØ© Ù…Ù† Ø§Ù„ØªÙ†ÙÙŠØ°.`,
  },
  {
    pattern: /^Dynamic run observed (\d+) network connection attempts\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `L'execution dynamique a observe ${match[1]} tentatives de connexion reseau.`
        : `Ø±ØµØ¯ Ø§Ù„ØªÙ†ÙÙŠØ° Ø§Ù„Ø¯ÙŠÙ†Ø§Ù…ÙŠÙƒÙŠ ${match[1]} Ù…Ø­Ø§ÙˆÙ„Ø§Øª Ø§ØªØµØ§Ù„ Ø´Ø¨ÙƒÙŠ.`,
  },
  {
    pattern: /^Content analysis found (\d+) suspicious indicators\.$/,
    render: (match, language) =>
      language === 'fr'
        ? `L'analyse du contenu a trouve ${match[1]} indicateurs suspects.`
        : `ÙˆØ¬Ø¯ ØªØ­Ù„ÙŠÙ„ Ø§Ù„Ù…Ø­ØªÙˆÙ‰ ${match[1]} Ù…Ø¤Ø´Ø±Ø§Øª Ù…Ø´Ø¨ÙˆÙ‡Ø©.`,
  },
  {
    pattern: /^Enter (MD5|SHA1|SHA256) hash \(e\.g\., (.+)\)$/,
    render: (match, language) =>
      language === 'fr'
        ? `Entrez le hash ${match[1]} (ex. : ${match[2]})`
        : `Ø§Ø¯Ø®Ù„ Ø¨ØµÙ…Ø© ${match[1]} (Ù…Ø«Ø§Ù„: ${match[2]})`,
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
    .map(([source, translations]) => [source, safeTranslation(translations[language], source)] as const)
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

function isCorruptedTranslation(value: string): boolean {
  return /[ØÙÂÃ]/.test(value);
}

function safeTranslation(value: string | undefined, fallback: string): string | undefined {
  if (!value) {
    return undefined;
  }
  return isCorruptedTranslation(value) ? fallback : value;
}

function translateLiteral(text: string, language: Language): string {
  if (language === 'en') {
    return text;
  }

  const normalized = normalizeLiteralKey(text);
  if (!normalized) {
    return text;
  }

  if (language === 'ar' && arabicLiteralOverrides[normalized]) {
    return preserveWhitespace(text, arabicLiteralOverrides[normalized]);
  }

  const exact = safeTranslation(literalTranslations[normalized]?.[language], normalized);
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
      t: (key: string, fallback?: string) =>
        language === 'ar' && arabicKeyOverrides[key]
          ? arabicKeyOverrides[key]
          : safeTranslation(keyTranslations[key]?.[language], fallback ?? key) ?? fallback ?? key,
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

