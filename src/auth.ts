import { sha256 } from './crypto';
import { ApiError } from './errors';
import type { Database } from './database';
import type { Env } from './types';

export async function rateLimit(
  db: Database,
  scope: string,
  identity: string,
  limit: number,
  window: number,
) {
  const allowed = await db.rpc<boolean>('cubauth_rate_limit', {
    p_key: `${scope}:${await sha256(identity.toLowerCase())}`,
    p_limit: limit,
    p_window: window,
  });
  if (!allowed) throw new ApiError(429, 'TooManyRequests', 'Too many attempts. Try again later.');
}

export const WEB_SESSION_TTL = 28800;

export function tokenTtl(env: Env): number {
  const ttl = Number(env.TOKEN_TTL_SECONDS);
  return Number.isInteger(ttl) && ttl >= 60 && ttl <= 2592000 ? ttl : 1296000;
}
