import { Hono, type Context } from 'hono';
import { rateLimit, tokenTtl, withVerifiedPassword } from './auth';
import { newToken, sha256 } from './crypto';
import { ApiError, badRequest } from './errors';
import { sessionResponse } from './profiles';
import { Supabase } from './supabase';
import type { Env, Profile, Session } from './types';
import { ip, jsonBody, text } from './validation';

interface Account {
  user_id: string; profile: Profile; email: string; email_confirmed: boolean;
  pending_email: string | null; created_at: string;
  name_history: { previous_name: string; new_name: string; changed_at: string }[];
  history_total: number;
}
type Ctx = Context<{ Bindings: Env }>;
const clientIp = (c: Ctx) => ip(c.req.header('CF-Connecting-IP') ?? '127.0.0.1');
const redirectUrl = (env: Env) => env.ACCOUNT_URL ? `${env.ACCOUNT_URL.replace(/\/$/, '')}/account` : `${env.PUBLIC_URL.replace(/\/$/, '')}/account`;
const emailAddress = (value: unknown) => {
  const email = text(value, 'email', 254).trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw badRequest('Use a valid email address.');
  return email;
};

async function currentAccount(c: Ctx) {
  const token = c.req.header('Authorization')?.match(/^Bearer ([a-f0-9]{64})$/i)?.[1];
  if (!token) throw new ApiError(401, 'Unauthorized', 'Missing bearer token.');
  const db = new Supabase(c.env), hash = await sha256(token);
  const account = await db.rpc<Account | null>('cubauth_account', { p_hash: hash });
  if (!account) throw new ApiError(401, 'Unauthorized', 'Invalid session.');
  return { db, hash, account };
}

async function authResult(response: Response): Promise<Record<string, unknown>> {
  const body = await response.json().catch(() => null) as Record<string, unknown> | null;
  if (response.ok && body) return body;
  const code = body?.code ?? body?.error_code;
  if (response.status === 429) throw new ApiError(429, 'TooManyRequests', 'Too many attempts. Try again later.');
  if (code === 'weak_password') throw badRequest('Choose a stronger password that meets the project requirements.');
  if (code === 'same_password') throw badRequest('The new password must be different from the current one.');
  if (code === 'email_exists' || code === 'user_already_exists') throw new ApiError(409, 'EmailUnavailable', 'That email cannot be used.');
  if (code === 'reauthentication_needed' || code === 'reauthentication_not_valid') throw new ApiError(403, 'ReauthenticationRequired', 'Supabase requires additional identity verification. Check the Auth configuration.');
  if (response.status >= 500 || !body) throw new ApiError(503, 'AuthUpdateUnavailable', 'Supabase Auth could not update the account. Check its Auth logs and SMTP configuration.');
  throw new ApiError(400, 'AccountUpdateFailed', 'Supabase could not complete this change. Check the entered values and email settings.');
}

async function reauthenticate<T>(c: Ctx, db: Supabase, account: Account, password: string, action: (token: string) => Promise<T>) {
  await rateLimit(db, 'account-write-user', account.user_id, 10, 600);
  return withVerifiedPassword(db, account.email, password, clientIp(c), async (userId, token) => {
    if (userId !== account.user_id) throw new ApiError(403, 'ForbiddenOperationException', 'Account mismatch.');
    return action(token);
  });
}

export const accountRoutes = new Hono<{ Bindings: Env }>();

accountRoutes.get('/me', async c => {
  const { account } = await currentAccount(c);
  return c.json({
    email: account.email, emailConfirmed: account.email_confirmed,
    pendingEmail: account.pending_email, createdAt: account.created_at,
    nameHistory: account.name_history.map(item => ({ previousName: item.previous_name, newName: item.new_name, changedAt: item.changed_at })),
    historyTotal: account.history_total,
  });
});

accountRoutes.post('/username', async c => {
  const body = await jsonBody(c.req.raw);
  const name = text(body.username, 'username', 16), password = text(body.currentPassword, 'currentPassword');
  if (!/^[A-Za-z0-9_]{3,16}$/.test(name)) throw badRequest('Username must contain 3–16 letters, digits or underscores.');
  const { db, hash, account } = await currentAccount(c);
  return reauthenticate(c, db, account, password, async () => {
    const token = newToken();
    const result = await db.rpc<Session | { error: string } | null>('cubauth_rename_profile', {
      p_hash: hash, p_name: name, p_new_hash: await sha256(token), p_ttl: tokenTtl(c.env),
    });
    if (!result) throw new ApiError(401, 'Unauthorized', 'Invalid session.');
    if ('error' in result) throw new ApiError(409, result.error, 'That username is already taken.');
    return c.json({ session: sessionResponse(result, token, false) });
  });
});

accountRoutes.post('/email', async c => {
  const body = await jsonBody(c.req.raw);
  const email = emailAddress(body.email), password = text(body.currentPassword, 'currentPassword');
  const { db, account } = await currentAccount(c);
  if (email.toLowerCase() === account.email.toLowerCase()) throw badRequest('Choose a different email address.');
  return reauthenticate(c, db, account, password, async token => {
    await authResult(await db.request(`/auth/v1/user?redirect_to=${encodeURIComponent(redirectUrl(c.env))}`, {
      method: 'PUT', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ email }),
    }, false));
    return c.json({ message: 'Email change requested. Follow the confirmation links if required by Supabase.' });
  });
});

accountRoutes.post('/password', async c => {
  const body = await jsonBody(c.req.raw);
  const password = text(body.currentPassword, 'currentPassword'), next = text(body.newPassword, 'newPassword');
  if (next.length < 10) throw badRequest('The new password must contain at least 10 characters.');
  if (password === next) throw badRequest('The new password must be different from the current one.');
  const { db, hash, account } = await currentAccount(c);
  const session = await db.rpc<Session | null>('cubauth_session', { p_hash: hash });
  if (!session) throw new ApiError(401, 'Unauthorized', 'Invalid session.');
  return reauthenticate(c, db, account, password, async supabaseToken => {
    await authResult(await db.request('/auth/v1/user', {
      method: 'PUT', headers: { Authorization: `Bearer ${supabaseToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ password: next }),
    }, false));
    // The password trigger revokes all old Yggdrasil sessions. Keep this tab signed
    // in by issuing a fresh one only after Supabase confirms the password change.
    const token = newToken();
    const renewed = await db.rpc<Session | null>('cubauth_issue_session', {
      p_user_id: account.user_id, p_hash: await sha256(token), p_client: session.client_token, p_ttl: tokenTtl(c.env),
    });
    if (!renewed) throw new ApiError(401, 'Unauthorized', 'Sign in again with the new password.');
    return c.json({ session: sessionResponse(renewed, token, false) });
  });
});

accountRoutes.post('/resend-verification', async c => {
  const body = await jsonBody(c.req.raw), email = emailAddress(body.email);
  const db = new Supabase(c.env);
  await rateLimit(db, 'verify-email-ip', clientIp(c), 5, 3600);
  await rateLimit(db, 'verify-email-address', email, 3, 600);
  const response = await db.request(`/auth/v1/resend?redirect_to=${encodeURIComponent(redirectUrl(c.env))}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type: 'signup', email }),
  }, false);
  if (response.status === 429) throw new ApiError(429, 'TooManyRequests', 'Too many emails requested. Try again later.');
  if (response.status === 401 || response.status === 403 || response.status >= 500) {
    throw new ApiError(503, 'VerificationUnavailable', 'Supabase could not send the email. Check Auth and SMTP configuration.');
  }
  // Same result for nonexistent, already-confirmed and eligible accounts.
  return c.json({ message: 'If this account needs confirmation, a new link will be sent to its email.' }, 202);
});
