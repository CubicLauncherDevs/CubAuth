import { ApiError } from './errors';
import type { Env } from './types';

export class Supabase {
  private origin: string;

  constructor(private env: Env) {
    const invalidConfig = () => new ApiError(503, 'ConfigurationError', 'Set SUPABASE_URL to the real Project URL from Supabase (for example, https://<project-ref>.supabase.co).');
    let url: URL;
    try { url = new URL(env.SUPABASE_URL); }
    catch { throw invalidConfig(); }
    if (!['http:', 'https:'].includes(url.protocol) || url.hostname === 'your_project.supabase.co'
      || url.pathname !== '/' || url.search || url.hash || url.username || url.password) throw invalidConfig();
    this.origin = url.origin;
  }

  async request(path: string, init: RequestInit = {}, admin = true): Promise<Response> {
    const key = admin ? this.env.SUPABASE_SERVICE_ROLE_KEY : this.env.SUPABASE_ANON_KEY;
    const headers = new Headers(init.headers);
    headers.set('apikey', key);
    // New sb_secret/sb_publishable keys are not JWTs. Legacy keys also need Bearer auth.
    if (!key.startsWith('sb_') && !headers.has('Authorization')) headers.set('Authorization', `Bearer ${key}`);
    const response = await fetch(`${this.origin}${path}`, {
      ...init, headers, signal: AbortSignal.timeout(15_000),
    });
    if (response.status === 530) {
      console.error('Supabase connection failed', new URL(this.origin).hostname, response.status);
      throw new ApiError(503, 'ServiceUnavailable', 'Supabase could not be reached (HTTP 530). Check SUPABASE_URL and the project domain.');
    }
    return response;
  }

  async rpc<T>(name: string, args: Record<string, unknown> = {}): Promise<T> {
    const res = await this.request(`/rest/v1/rpc/${name}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(args),
    });
    if (!res.ok) {
      // Never log backend bodies: they can contain credentials or account data.
      console.error('Database operation failed', name, res.status);
      throw new ApiError(503, 'ServiceUnavailable', 'Database unavailable.');
    }
    return res.json() as Promise<T>;
  }
}
