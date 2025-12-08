// Simple API client for RedFixer backend
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';
const API_KEY = import.meta.env.VITE_API_KEY || 'change-me-in-production';

export interface ScanListItem {
  scan_id: string;
  vuln_id: string;
  status: string;
  host_count: number;
  created_at: string;
}

export interface HealthResponse {
  status: string;
  version: string;
}

async function fetchAPI<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': API_KEY,
      ...options?.headers,
    },
  });

  if (!response.ok) {
    throw new Error(`API Error: ${response.status} ${response.statusText}`);
  }

  return response.json();
}

export const api = {
  health: () => fetchAPI<HealthResponse>('/health'),
  listScans: (limit = 10) => fetchAPI<ScanListItem[]>(`/scans?limit=${limit}`),
};
