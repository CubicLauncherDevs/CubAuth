import { ApiError, type ErrorDetails } from './errors';
import { databaseCode, databaseException } from './supabase-errors';
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
    const operation = path.match(/^\/rest\/v1\/rpc\/(cubauth_[a-z_]+)$/)?.[1]
      ?? (path.startsWith('/auth/v1/signup') ? 'auth_signup'
        : path.startsWith('/auth/v1/token') ? 'auth_login'
          : path.startsWith('/auth/v1/logout') ? 'auth_logout'
            : path.startsWith('/storage/v1/object/') ? 'storage_upload' : 'supabase_request');
    const key = admin ? this.env.SUPABASE_SERVICE_ROLE_KEY : this.env.SUPABASE_ANON_KEY;
    const keyName = admin ? 'SUPABASE_SERVICE_ROLE_KEY' : 'SUPABASE_ANON_KEY';
    if (typeof key !== 'string' || !key.trim()) {
      this.fail('SupabaseKeyMissing', `Configure ${keyName} as a Cloudflare Worker secret.`, { service: 'supabase', operation });
    }
    if (admin && key.startsWith('sb_publishable_')) {
      this.fail('SupabaseCredentialsInvalid', 'SUPABASE_SERVICE_ROLE_KEY contains a publishable key. Replace it with the secret/service_role key from the same Supabase project.', { service: 'supabase', operation });
    }
    const headers = new Headers(init.headers);
    headers.set('apikey', key);
    // New sb_secret/sb_publishable keys are not JWTs. Legacy keys also need Bearer auth.
    if (!key.startsWith('sb_') && !headers.has('Authorization')) headers.set('Authorization', `Bearer ${key}`);
    let response: Response;
    try {
      response = await fetch(`${this.origin}${path}`, {
        ...init, headers, signal: AbortSignal.timeout(15_000),
      });
    } catch (error) {
      const timeout = error instanceof Error && ['AbortError', 'TimeoutError'].includes(error.name);
      this.fail(timeout ? 'SupabaseTimeout' : 'SupabaseConnectionFailed', timeout
        ? 'Supabase did not respond within 15 seconds. Check project availability and retry.'
        : 'Could not connect to Supabase. Check SUPABASE_URL, DNS and project availability.',
      { service: 'supabase', operation });
    }
    if (response.status === 530) {
      this.fail('SupabaseConnectionFailed', 'Supabase could not be reached (HTTP 530). Check SUPABASE_URL and the project domain.',
        { service: 'supabase', operation, upstreamStatus: response.status });
    }
    return response;
  }

  async rpc<T>(name: string, args: Record<string, unknown> = {}): Promise<T> {
    const res = await this.request(`/rest/v1/rpc/${name}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(args),
    });
    if (!res.ok) {
      const code = await databaseCode(res);
      const exception = databaseException(res.status, code);
      this.fail(exception.error, exception.message, {
        service: 'supabase', operation: name, upstreamStatus: res.status, ...(code ? { upstreamCode: code } : {}),
      });
    }
    try { return await res.json() as T; }
    catch {
      this.fail('SupabaseInvalidResponse', 'The Supabase Data API returned invalid JSON. Check SUPABASE_URL and any proxy in front of the project.',
        { service: 'supabase', operation: name, upstreamStatus: res.status });
    }
  }

  private fail(code: string, message: string, details: ErrorDetails): never {
    // Only controlled fields: never log backend messages, SQL details, credentials or arguments.
    console.error('Supabase operation failed', { error: code, host: new URL(this.origin).hostname, ...details });
    throw new ApiError(503, code, message, details);
  }
}
