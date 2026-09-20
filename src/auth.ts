import { sha256 } from './crypto';
import { ApiError, invalidCredentials } from './errors';
import { Supabase } from './supabase';
import type { Env } from './types';

export async function rateLimit(db: Supabase, scope: string, identity: string, limit: number, window: number) {
  const allowed = await db.rpc<boolean>('cubauth_rate_limit', {
    p_key: `${scope}:${await sha256(identity.toLowerCase())}`, p_limit: limit, p_window: window,
  });
  if (!allowed) throw new ApiError(429, 'TooManyRequests', 'Too many attempts. Try again later.');
}

export async function withVerifiedPassword<T>(db: Supabase, username: string, password: string, clientIp: string,
  action: (userId: string, supabaseToken: string) => Promise<T>): Promise<T> {
  await rateLimit(db, 'auth-ip', clientIp, 40, 600);
  const identity = await db.rpc<{ email: string; user_id: string } | null>('cubauth_login_identity', { p_username: username });
  await rateLimit(db, 'auth-account', identity?.user_id ?? username, 10, 600);
  // Use the Auth endpoint for unknown accounts too, with the same external error.
  const res = await db.request('/auth/v1/token?grant_type=password', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: identity?.email ?? (username.includes('@') ? username : `${username}@invalid.invalid`), password }),
  }, false);
  if (res.status === 429) throw new ApiError(429, 'TooManyRequests', 'Too many attempts. Try again later.');
  if (res.status >= 500) throw new ApiError(503, 'ServiceUnavailable', 'Authentication unavailable.');
  if (!res.ok) throw invalidCredentials();
  const data = await res.json() as { user?: { id: string }; access_token?: string };
  try {
    if (!identity || data.user?.id !== identity.user_id || !data.access_token) throw invalidCredentials();
    return await action(identity.user_id, data.access_token);
  } finally {
    if (data.access_token) {
      // Short-lived Supabase session used only by the Worker; never returned to the launcher/browser.
      await db.request('/auth/v1/logout?scope=local', {
        method: 'POST', headers: { Authorization: `Bearer ${data.access_token}` },
      }, false).catch(() => {});
    }
  }
}

export const verifyPassword = (db: Supabase, username: string, password: string, clientIp: string) =>
  withVerifiedPassword(db, username, password, clientIp, async userId => userId);

export function tokenTtl(env: Env): number {
  const ttl = Number(env.TOKEN_TTL_SECONDS);
  return Number.isInteger(ttl) && ttl >= 60 && ttl <= 2592000 ? ttl : 1296000;
}
