import { Hono, type Context } from 'hono';
import { accountRoutes } from './account';
import { importRoutes } from './imports';
import { rateLimit, tokenTtl } from './auth';
import { authenticateLauncher } from './launcher-tokens';
import { oauthRoutes } from './oauth';
import { compactUuid, newToken, pem, sha256 } from './crypto';
import { ApiError, badRequest, invalidToken } from './errors';
import { fullProfile, sessionResponse } from './profiles';
import { MAX_SKIN_BYTES, sanitizeSkin } from './skins';
import { Database } from './database';
import type { Env, Profile, Session } from './types';
import { ip, jsonBody, jsonValue, optionalClient, readBody, requestUser, text, uuid } from './validation';

type App = { Bindings: Env };
const app = new Hono<App>();
const database = (c: Context<App>) => new Database(c.env);
const clientIp = (c: Context<App>) => ip(c.req.header('CF-Connecting-IP') ?? '127.0.0.1');
const baseUrl = (env: Env) => env.PUBLIC_URL.replace(/\/$/, '');
const accountLinks = (env: Env) => env.ACCOUNT_URL ? {
  homepage: `${env.ACCOUNT_URL.replace(/\/$/, '')}/account`,
  register: `${env.ACCOUNT_URL.replace(/\/$/, '')}/register`,
  login: `${env.ACCOUNT_URL.replace(/\/$/, '')}/login`,
} : {
  homepage: `${baseUrl(env)}/account`, register: `${baseUrl(env)}/account#register`, login: `${baseUrl(env)}/account`,
};

app.use('*', async (c, next) => {
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('Referrer-Policy', 'no-referrer');
  c.header('Cache-Control', 'no-store');
  c.header('Vary', 'Origin');
  const origin = c.req.header('Origin');
  const allowedOrigin = !!origin && (origin === new URL(c.req.url).origin
    || (c.env.WEB_ORIGINS ?? '').split(',').map(value => value.trim()).filter(Boolean).includes(origin));
  if (allowedOrigin) c.header('Access-Control-Allow-Origin', origin!);
  if (c.req.method === 'OPTIONS' && c.req.header('Access-Control-Request-Method')) {
    if (!allowedOrigin) throw new ApiError(403, 'ForbiddenOperationException', 'Origin not allowed.');
    const method = c.req.header('Access-Control-Request-Method')!;
    const headers = (c.req.header('Access-Control-Request-Headers') ?? '').toLowerCase().split(',').map(value => value.trim()).filter(Boolean);
    if (!['GET', 'HEAD', 'POST', 'PUT', 'DELETE'].includes(method)
      || headers.some(header => !['content-type', 'authorization'].includes(header))) {
      throw new ApiError(403, 'ForbiddenOperationException', 'CORS method or headers not allowed.');
    }
    c.header('Access-Control-Allow-Methods', 'GET, HEAD, POST, PUT, DELETE, OPTIONS');
    c.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    c.header('Access-Control-Max-Age', '3600');
    return c.body(null, 204);
  }
  if (!['GET', 'HEAD', 'OPTIONS'].includes(c.req.method)) {
    // Native launchers omit Origin. Browser requests use an exact configured origin.
    if (origin && !allowedOrigin) throw new ApiError(403, 'ForbiddenOperationException', 'Origin not allowed.');
  }
  await next();
});

app.onError((error, c) => {
  if (error instanceof ApiError) {
    if (error.status === 429) c.header('Retry-After', '600');
    return c.newResponse(JSON.stringify({ error: error.code, errorMessage: error.message,
      ...(error.details ? { details: error.details } : {}),
    }), error.status as 400, { 'Content-Type': 'application/json; charset=utf-8' });
  }
  // Do not log request bodies, tokens, or raw upstream error messages.
  console.error('Unhandled request failure', error.name);
  return c.json({ error: 'InternalServerError', errorMessage: 'Service temporarily unavailable.' }, 500);
});
app.notFound(c => c.json({ error: 'NotFound', errorMessage: 'Unknown endpoint.' }, 404));

app.get('/', c => {
  if (!c.env.SIGNING_PUBLIC_KEY) throw new ApiError(503, 'ServiceUnavailable', 'Signing key not configured.');
  return c.json({
    meta: {
      serverName: c.env.SERVER_NAME || 'CubAuth', implementationName: 'CubAuth', implementationVersion: '1.0.0',
      links: { homepage: accountLinks(c.env).homepage, register: accountLinks(c.env).register },
      registrationEnabled: c.env.ALLOW_REGISTRATION === 'true',
      'feature.non_email_login': true,
      'feature.no_mojang_namespace': true,
      'feature.enable_profile_key': false,
    },
    skinDomains: [new URL(c.env.PUBLIC_URL).hostname],
    discordInviteUrl: c.env.DISCORD_INVITE_URL || 'https://discord.com/invite/7VaqSrPukm',
    signaturePublickey: pem(c.env.SIGNING_PUBLIC_KEY),
  });
});

app.route('/account', accountRoutes);
app.route('/account/import', importRoutes);
app.route('/discord', oauthRoutes);

app.post('/account/register', async c => {
  return c.json({ error: 'DiscordRequired', errorMessage: 'Create your account with Discord on the account website.' }, 410);
});

app.post('/authserver/authenticate', async c => {
  const data = await jsonBody(c.req.raw);
  const username = text(data.username, 'username', 254).trim();
  const password = text(data.password, 'password');
  const client = optionalClient(data.clientToken) ?? compactUuid(crypto.randomUUID());
  const includeUser = requestUser(data.requestUser);
  if (data.agent !== undefined) {
    const agent = data.agent as { name?: string; version?: number } | null;
    if (agent?.name !== 'Minecraft' || agent?.version !== 1) throw badRequest('Unsupported agent.');
  }
  const db = database(c);
  await rateLimit(db, 'launcher-auth-ip', clientIp(c), 40, 600);
  await rateLimit(db, 'launcher-auth-name', username, 10, 600);
  const { session, accessToken } = await authenticateLauncher(c.env, username, password, client);
  return c.json(sessionResponse(session, accessToken, includeUser, true));
});

app.post('/authserver/refresh', async c => {
  const data = await jsonBody(c.req.raw);
  const hash = await sha256(text(data.accessToken, 'accessToken'));
  const client = optionalClient(data.clientToken);
  const includeUser = requestUser(data.requestUser);
  const db = database(c);
  const current = await db.session(hash, client, 'launcher');
  if (!current) throw invalidToken();
  if (data.selectedProfile !== undefined) {
    if (!await db.rpc<Session | null>('cubauth_session', { p_hash: hash, p_client: client })) throw invalidToken();
    throw badRequest('Access token already has a profile assigned.');
  }
  const token = newToken();
  const session = await db.rpc<Session | null>('cubauth_refresh', {
    p_hash: hash, p_new_hash: await sha256(token), p_client: client, p_ttl: tokenTtl(c.env),
  });
  if (!session) throw invalidToken();
  return c.json(sessionResponse(session, token, includeUser));
});

app.post('/authserver/validate', async c => {
  const data = await jsonBody(c.req.raw);
  const session = await database(c).rpc<Session | null>('cubauth_session', {
    p_hash: await sha256(text(data.accessToken, 'accessToken')), p_client: optionalClient(data.clientToken),
  });
  if (!session) throw invalidToken();
  return c.body(null, 204);
});

app.post('/authserver/invalidate', async c => {
  const data = await jsonBody(c.req.raw);
  await database(c).rpc('cubauth_invalidate', { p_hash: await sha256(text(data.accessToken, 'accessToken')) });
  return c.body(null, 204);
});

app.post('/authserver/signout', async c => {
  const data = await jsonBody(c.req.raw);
  const db = database(c);
  await rateLimit(db, 'launcher-auth-ip', clientIp(c), 40, 600);
  const { session } = await authenticateLauncher(c.env, text(data.username, 'username', 16), text(data.password, 'password'), compactUuid(crypto.randomUUID()));
  await db.db.batch([
    db.statement("DELETE FROM sessions WHERE discord_id = ? AND kind = 'launcher'", session.discord_id),
    db.statement('DELETE FROM launcher_tokens WHERE discord_id = ?', session.discord_id),
  ]);
  return c.body(null, 204);
});

app.post('/sessionserver/session/minecraft/join', async c => {
  const data = await jsonBody(c.req.raw);
  const success = await database(c).rpc<boolean>('cubauth_join', {
    p_hash: await sha256(text(data.accessToken, 'accessToken')),
    p_profile: uuid(data.selectedProfile), p_server: text(data.serverId, 'serverId', 128), p_ip: clientIp(c),
  });
  if (!success) throw invalidToken();
  return c.body(null, 204);
});

app.get('/sessionserver/session/minecraft/hasJoined', async c => {
  const profile = await database(c).rpc<Profile | null>('cubauth_has_joined', {
    p_name: text(c.req.query('username'), 'username', 16), p_server: text(c.req.query('serverId'), 'serverId', 128),
    p_ip: c.req.query('ip') === undefined ? null : ip(c.req.query('ip')!),
  });
  return profile ? c.json(await fullProfile(profile, c.env, true)) : c.body(null, 204);
});

app.get('/sessionserver/session/minecraft/profile/:uuid', async c => {
  const unsigned = c.req.query('unsigned');
  if (unsigned !== undefined && !['true', 'false'].includes(unsigned)) throw badRequest('Invalid unsigned parameter.');
  const profile = await database(c).rpc<Profile | null>('cubauth_profile', { p_id: uuid(c.req.param('uuid')) });
  return profile ? c.json(await fullProfile(profile, c.env, unsigned === 'false')) : c.body(null, 204);
});

app.post('/api/profiles/minecraft', async c => {
  const data = await jsonValue(c.req.raw);
  if (!Array.isArray(data) || data.length > 100 || data.some(name => typeof name !== 'string' || !/^[A-Za-z0-9_]{3,16}$/.test(name))) throw badRequest('Expected up to 100 player names.');
  return c.json(await database(c).rpc<{ id: string; name: string }[]>('cubauth_profiles', { p_names: data }));
});

async function skinOwner(c: Context<App>): Promise<{ db: Database; hash: string; profileId: string }> {
  const token = c.req.header('Authorization')?.match(/^Bearer ([a-f0-9]{64})$/i)?.[1];
  if (!token) throw new ApiError(401, 'Unauthorized', 'Missing or invalid bearer token.');
  const hash = await sha256(token);
  const db = database(c);
  const session = await db.session(hash);
  if (!session) throw new ApiError(401, 'Unauthorized', 'Invalid token.');
  const profileId = uuid(c.req.param('uuid'));
  if (session.profile.id !== profileId) throw new ApiError(403, 'ForbiddenOperationException', 'This profile does not belong to the session.');
  await rateLimit(db, 'skin-user', session.user_id, 20, 600);
  return { db, hash, profileId };
}

app.put('/api/user/profile/:uuid/skin', async c => {
  const { db, hash, profileId } = await skinOwner(c);
  const contentType = c.req.header('Content-Type') ?? '';
  if (!contentType.toLowerCase().startsWith('multipart/form-data;')) throw new ApiError(415, 'UnsupportedMediaType', 'Use multipart/form-data.');
  const body = await readBody(c.req.raw, MAX_SKIN_BYTES + 8192);
  let form: FormData;
  try { form = await new Response(body, { headers: { 'Content-Type': contentType } }).formData(); }
  catch { throw badRequest('Invalid multipart body.'); }
  const file = form.get('file');
  const modelValue = form.get('model') ?? '';
  if (!['', 'default', 'slim'].includes(String(modelValue))) throw badRequest('Invalid skin model.');
  const model = modelValue === 'slim' ? 'slim' : 'default';
  if (!file || typeof file === 'string' || file.size > MAX_SKIN_BYTES) throw badRequest('Supply a PNG file up to 128 KiB.');
  const png = await sanitizeSkin(new Uint8Array(await file.arrayBuffer()), model);
  const skinHash = await sha256(png);
  await c.env.SKINS.put(skinHash, png, { httpMetadata: { contentType: 'image/png', cacheControl: 'public, max-age=31536000, immutable' } });
  const updated = await db.rpc<boolean>('cubauth_set_skin', { p_hash: hash, p_profile: profileId, p_skin: skinHash, p_model: model });
  if (!updated) throw new ApiError(401, 'Unauthorized', 'Session expired while uploading.');
  return c.body(null, 204);
});

app.delete('/api/user/profile/:uuid/skin', async c => {
  const { db, hash, profileId } = await skinOwner(c);
  if (!await db.rpc<boolean>('cubauth_set_skin', { p_hash: hash, p_profile: profileId, p_skin: null, p_model: 'default' })) throw new ApiError(401, 'Unauthorized', 'Invalid token.');
  return c.body(null, 204);
});

app.get('/textures/:hash', async c => {
  const hash = c.req.param('hash');
  if (!/^[a-f0-9]{64}$/.test(hash)) throw badRequest('Invalid texture hash.');
  const object = await c.env.SKINS.get(hash);
  if (!object) return c.body(null, 404);
  c.header('Content-Type', 'image/png');
  c.header('Cache-Control', 'public, max-age=31536000, immutable');
  c.header('Access-Control-Allow-Origin', '*');
  c.header('ETag', object.httpEtag);
  return c.body(object.body);
});
app.get('/account', c => {
  if (!c.env.ACCOUNT_URL) throw new ApiError(503, 'ConfigurationError', 'Configure ACCOUNT_URL.');
  return c.redirect(accountLinks(c.env).homepage, 302);
});

export { app };
export default {
  fetch: app.fetch,
  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(new Database(env).rpc('cubauth_cleanup'));
  },
} satisfies ExportedHandler<Env>;
