import { ApiError } from './errors';
import type { Env } from './types';

export class Supabase {
  constructor(private env: Env) {}

  async request(path: string, init: RequestInit = {}, admin = true): Promise<Response> {
    const key = admin ? this.env.SUPABASE_SERVICE_ROLE_KEY : this.env.SUPABASE_ANON_KEY;
    const headers = new Headers(init.headers);
    headers.set('apikey', key);
    // New sb_secret/sb_publishable keys are not JWTs. Legacy keys also need Bearer auth.
    if (!key.startsWith('sb_') && !headers.has('Authorization')) headers.set('Authorization', `Bearer ${key}`);
    return fetch(`${this.env.SUPABASE_URL.replace(/\/$/, '')}${path}`, {
      ...init, headers, signal: AbortSignal.timeout(15_000),
    });
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
