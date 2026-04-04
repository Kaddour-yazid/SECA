const envApiBase = (import.meta.env.VITE_API_BASE_URL || '').trim();

function getDefaultApiBase(): string {
  if (typeof window === 'undefined') {
    return 'http://127.0.0.1:8000';
  }

  const { hostname } = window.location;
  if (!hostname || hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
    return 'http://127.0.0.1:8000';
  }

  return `http://${hostname}:8000`;
}

export const API_BASE_URL = (envApiBase || getDefaultApiBase()).replace(/\/+$/, '');

export function apiUrl(path: string): string {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  return `${API_BASE_URL}${normalizedPath}`;
}
