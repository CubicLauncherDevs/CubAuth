import { Hono } from 'hono';
import { rateLimit } from './auth';
import { newToken, sha256 } from './crypto';
import { Database } from './database';
import { ApiError } from './errors';
import type { Env } from './types';
import { jsonBody, text } from './validation';

interface LegacyProfile {
  id: string;
  name: string;
  skinHash: string | null;
  skinModel: 'default' | 'slim';
  createdAt: number;
}

interface LegacyHistoryEntry {
  previousName: string;
  newName: string;
  changedAt: number;
}

interface LegacyAccount {
  profile?: { id?: unknown; name?: unknown; skin_hash?: unknown; skin_model?: unknown };
  created_at?: unknown;
  name_history?: unknown;
}

interface LegacyTicketRow {
  legacy_user_id: string;
  profile: string;
  history: string;
}

const unavailable = () =>
  new ApiError(503, 'MigrationUnavailable', 'The legacy account service is unavailable.');
const invalidLegacyCredentials = () =>
  new ApiError(403, 'MigrationCredentialsInvalid', 'Invalid legacy username or password.');

const origin = (env: Env): string => {
  let url: URL;
  try {
    url = new URL(env.SUPABASE_URL ?? '');
  } catch {
    throw unavailable();
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.pathname !== '/') throw unavailable();
  return url.origin;
};

async function supabaseRequest(
  env: Env,
  path: string,
  init: RequestInit = {},
  admin = true,
): Promise<Response> {
  const key = admin ? env.SUPABASE_SERVICE_ROLE_KEY : env.SUPABASE_ANON_KEY;
  if (typeof key !== 'string' || !key.trim()) throw unavailable();
  const headers = new Headers(init.headers);
  headers.set('apikey', key);
  if (!key.startsWith('sb_') && !headers.has('Authorization'))
    headers.set('Authorization', `Bearer ${key}`);
  try {
    return await fetch(`${origin(env)}${path}`, {
      ...init,
      headers,
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    throw unavailable();
  }
}

async function rpc<T>(env: Env, name: string, args: Record<string, unknown>): Promise<T> {
  const response = await supabaseRequest(env, `/rest/v1/rpc/${name}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(args),
  });
  if (!response.ok) throw unavailable();
  return (await response.json()) as T;
}

const seconds = (value: unknown): number | null => {
  if (typeof value !== 'string') return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? Math.floor(parsed / 1000) : null;
};

function snapshot(account: LegacyAccount): { profile: LegacyProfile; history: LegacyHistoryEntry[] } {
  const source = (account.profile ?? {}) as {
    id?: unknown;
    name?: unknown;
    skin_hash?: unknown;
    skin_model?: unknown;
  };
  const id = source.id,
    name = source.name;
  if (typeof id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id))
    throw new ApiError(409, 'MigrationProfileMissing', 'The legacy profile could not be found.');
  if (typeof name !== 'string' || !/^[A-Za-z0-9_]{3,16}$/.test(name))
    throw new ApiError(409, 'MigrationProfileMissing', 'The legacy profile could not be found.');
  const skinHash =
    typeof source.skin_hash === 'string' && /^[a-f0-9]{64}$/.test(source.skin_hash)
      ? source.skin_hash
      : null;
  const profile: LegacyProfile = {
    id: id.toLowerCase(),
    name,
    skinHash,
    skinModel: source.skin_model === 'slim' ? 'slim' : 'default',
    createdAt: seconds(account.created_at) ?? Math.floor(Date.now() / 1000),
  };
  const raw = Array.isArray(account.name_history) ? account.name_history : [];
  const history = raw
    .flatMap((item): LegacyHistoryEntry[] => {
      const entry = item as { previous_name?: unknown; new_name?: unknown; changed_at?: unknown };
      const changedAt = seconds(entry.changed_at);
      return typeof entry.previous_name === 'string' && typeof entry.new_name === 'string' && changedAt
        ? [{ previousName: entry.previous_name, newName: entry.new_name, changedAt }]
        : [];
    })
    .sort((a, b) => a.changedAt - b.changedAt);
  return { profile, history };
}

async function copySkin(env: Env, hash: string): Promise<string | null> {
  let response: Response;
  try {
    response = await fetch(`${origin(env)}/storage/v1/object/public/skins/${hash}`, {
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    throw unavailable();
  }
  if (!response.ok) throw unavailable();
  const reader = response.body?.getReader();
  if (!reader) throw unavailable();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 128 * 1024) throw unavailable();
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const png = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { png.set(chunk, offset); offset += chunk.length; }
  if (!png.length || png.length > 128 * 1024 || await sha256(png) !== hash)
    throw unavailable();
  await env.SKINS.put(hash, png, {
    httpMetadata: { contentType: 'image/png', cacheControl: 'public, max-age=31536000, immutable' },
  });
  return hash;
}

async function verifyLegacy(
  env: Env,
  db: Database,
  identifier: string,
  password: string,
  clientIp: string,
): Promise<string> {
  await rateLimit(db, 'migration-ip', clientIp, 40, 600);
  const identity = await rpc<{ email: string; user_id: string } | null>(
    env,
    'cubauth_login_identity',
    { p_username: identifier },
  );
  await rateLimit(db, 'migration-account', identity?.user_id ?? identifier, 10, 600);
  // Unknown accounts also hit the Auth endpoint so both cases look the same.
  const response = await supabaseRequest(
    env,
    '/auth/v1/token?grant_type=password',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email:
          identity?.email ?? (identifier.includes('@') ? identifier : `${identifier}@invalid.invalid`),
        password,
      }),
    },
    false,
  );
  if (response.status === 429)
    throw new ApiError(429, 'TooManyRequests', 'Too many attempts. Try again later.');
  if (response.status >= 500) throw unavailable();
  if (!response.ok) {
    const failure = (await response.json().catch(() => null)) as {
      error_code?: unknown;
      code?: unknown;
    } | null;
    const code = failure?.error_code ?? failure?.code;
    if (code === 'user_banned')
      throw new ApiError(403, 'AccountBanned', 'This account is suspended.');
    if (code === 'email_not_confirmed')
      throw new ApiError(403, 'EmailNotConfirmed', 'Confirm your email address first.');
    throw invalidLegacyCredentials();
  }
  const session = (await response.json()) as { user?: { id?: string }; access_token?: string };
  if (session.access_token) {
    const revoked = await supabaseRequest(env, '/auth/v1/logout?scope=local', {
      method: 'POST',
      headers: { Authorization: `Bearer ${session.access_token}` },
    }, false);
    if (!revoked.ok) throw unavailable();
  }
  if (!identity || session.user?.id !== identity.user_id) throw invalidLegacyCredentials();

  // Read the legacy profile through a short-lived Supabase session, then revoke it.
  const temporaryToken = newToken();
  const temporaryHash = await sha256(temporaryToken);
  try {
    const issued = await rpc<unknown>(env, 'cubauth_issue_session', {
      p_user_id: identity.user_id,
      p_hash: temporaryHash,
      p_client: 'legacy-migration',
      p_ttl: 600,
    });
    if (!issued) throw new ApiError(403, 'AccountBanned', 'This account is suspended.');
    const account = await rpc<LegacyAccount>(env, 'cubauth_account', { p_hash: temporaryHash });
    const { profile, history } = snapshot(account);
    if (profile.skinHash) profile.skinHash = await copySkin(env, profile.skinHash);
    const token = newToken();
    await db
      .statement(
        'INSERT INTO legacy_tickets(token_hash, legacy_user_id, profile, history, expires_at) VALUES (?, ?, ?, ?, unixepoch() + 600)',
        await sha256(token),
        identity.user_id,
        JSON.stringify(profile),
        JSON.stringify(history),
      )
      .run();
    return token;
  } finally {
    await rpc(env, 'cubauth_invalidate', { p_hash: temporaryHash }).catch(() => {});
  }
}

export const migrationRoutes = new Hono<{ Bindings: Env }>();

migrationRoutes.post('/verify', async (c) => {
  const body = await jsonBody(c.req.raw);
  const token = await verifyLegacy(
    c.env,
    new Database(c.env),
    text(body.identifier, 'identifier', 254).trim(),
    text(body.password, 'password'),
    c.req.header('CF-Connecting-IP') ?? '127.0.0.1',
  );
  return c.json({ token });
});

export async function linkLegacy(
  db: Database,
  token: string,
  discordId: string,
  discordEmail: string | null,
) {
  const hash = await sha256(token);
  const row = await db
    .statement(
      'SELECT legacy_user_id, profile, history FROM legacy_tickets WHERE token_hash = ? AND expires_at > unixepoch()',
      hash,
    )
    .first<LegacyTicketRow>();
  if (!row)
    throw new ApiError(403, 'MigrationExpired', 'Start the account migration again.');
  const profile = JSON.parse(row.profile) as LegacyProfile;
  const history = JSON.parse(row.history) as LegacyHistoryEntry[];
  const linkedByUser = await db
    .statement('SELECT discord_id FROM accounts WHERE legacy_user_id = ?', row.legacy_user_id)
    .first<{ discord_id: string }>();
  if (linkedByUser && linkedByUser.discord_id !== discordId)
    throw new ApiError(409, 'LegacyAlreadyLinked', 'That old account is already linked.');
  const linkedByUuid = await db
    .statement('SELECT discord_id FROM accounts WHERE id = ?', profile.id)
    .first<{ discord_id: string }>();
  if (linkedByUuid && linkedByUuid.discord_id !== discordId)
    throw new ApiError(409, 'LegacyAlreadyLinked', 'That old account is already linked.');
  const nameOwner = await db
    .statement('SELECT discord_id FROM profiles WHERE name = ? COLLATE NOCASE', profile.name)
    .first<{ discord_id: string }>();
  if (nameOwner && nameOwner.discord_id !== discordId)
    throw new ApiError(409, 'UsernameTaken', 'That player name is already taken.');
  try {
    await db.db.batch([
      db.statement(
        'INSERT INTO legacy_link_guards(id, valid) VALUES (?, CASE WHEN EXISTS (SELECT 1 FROM legacy_tickets WHERE token_hash = ? AND expires_at > unixepoch()) THEN 1 ELSE 0 END)',
        hash,
        hash,
      ),
      db.statement('DELETE FROM accounts WHERE discord_id = ?', discordId),
      db.statement(
        'INSERT INTO accounts(discord_id, id, legacy_user_id, discord_email, created_at) VALUES (?, ?, ?, ?, ?)',
        discordId,
        profile.id,
        row.legacy_user_id,
        discordEmail,
        profile.createdAt,
      ),
      db.statement(
        'INSERT INTO profiles(id, discord_id, name, skin_hash, skin_model) VALUES (?, ?, ?, ?, ?)',
        profile.id,
        discordId,
        profile.name,
        profile.skinHash,
        profile.skinModel,
      ),
      ...history.map((entry) =>
        db.statement(
          'INSERT INTO name_history(profile_id, previous_name, new_name, changed_at) VALUES (?, ?, ?, ?)',
          profile.id,
          entry.previousName,
          entry.newName,
          entry.changedAt,
        ),
      ),
      db.statement('DELETE FROM legacy_tickets WHERE token_hash = ?', hash),
      db.statement('DELETE FROM legacy_link_guards WHERE id = ?', hash),
    ]);
  } catch (error) {
    const message = String(error);
    if (message.includes('CHECK constraint failed'))
      throw new ApiError(403, 'MigrationExpired', 'Start the account migration again.');
    if (message.includes('accounts.id') || message.includes('accounts.legacy_user_id'))
      throw new ApiError(409, 'LegacyAlreadyLinked', 'That old account is already linked.');
    if (message.includes('profiles.name'))
      throw new ApiError(409, 'UsernameTaken', 'That player name is already taken.');
    throw error;
  }
}
