const envApiBase = (import.meta.env.VITE_API_BASE_URL || '').trim();

export const API_BASE_URL = (envApiBase || 'http://127.0.0.1:8000').replace(/\/+$/, '');

export function apiUrl(path: string): string {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  return `${API_BASE_URL}${normalizedPath}`;
}
