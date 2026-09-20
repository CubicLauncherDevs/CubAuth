import { PGlite } from '@electric-sql/pglite';
import { readFileSync } from 'node:fs';
import { URL as NodeURL } from 'node:url';
import { generateKeyPairSync } from 'node:crypto';
import { beforeAll, afterAll, beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { app } from '../src/index';
import { sha256 } from '../src/crypto';
import type { Env, Profile, Session } from '../src/types';

let db: PGlite;
const USER = '00000000-0000-4000-8000-000000000001';
const OTHER = '00000000-0000-4000-8000-000000000002';
let profile: Profile;
let other: Profile;
const keyPair = generateKeyPairSync('rsa', { modulusLength: 2048,
  privateKeyEncoding: { format: 'pem', type: 'pkcs8' }, publicKeyEncoding: { format: 'pem', type: 'spki' } });
const env = {
  PUBLIC_URL: 'https://auth.example.com', SERVER_NAME: 'Test', SUPABASE_URL: 'https://test.supabase.co',
  SUPABASE_ANON_KEY: 'sb_publishable_test', SUPABASE_SERVICE_ROLE_KEY: 'sb_secret_test',
  SIGNING_PRIVATE_KEY: keyPair.privateKey, SIGNING_PUBLIC_KEY: keyPair.publicKey,
  TOKEN_TTL_SECONDS: '1296000', ALLOW_REGISTRATION: 'true',
} as Env;

async function rpc<T = unknown>(name: string, args: Record<string, unknown> = {}): Promise<T> {
  if (!/^cubauth_[a-z_]+$/.test(name) || Object.keys(args).some(key => !/^p_[a-z_]+$/.test(key))) throw new Error('Bad RPC');
  const parameters = Object.keys(args).map((key, i) => `${key} => $${i + 1}`).join(', ');
  const result = await db.query<{ result: T }>(`select public.${name}(${parameters}) as result`, Object.values(args));
  return result.rows[0]!.result;
}

async function issue(user = USER, token = 'a'.repeat(64), client = 'launcher') {
  return rpc<Session>('cubauth_issue_session', { p_user_id: user, p_hash: await sha256(token), p_client: client, p_ttl: 3600 });
}

beforeAll(async () => {
  db = new PGlite();
  await db.exec(`
    create role anon; create role authenticated; create role service_role;
    create schema auth; create schema storage;
    create table auth.users(id uuid primary key, email text unique, raw_user_meta_data jsonb,
      banned_until timestamptz, encrypted_password text);
    create table storage.buckets(id text primary key, name text, public boolean, file_size_limit bigint, allowed_mime_types text[]);
  `);
  await db.exec(readFileSync(new NodeURL('../supabase/migrations/202609200001_cubauth.sql', import.meta.url), 'utf8'));
});
afterAll(async () => { await db.close(); });

beforeEach(async () => {
  await db.exec('truncate auth.users cascade; truncate cubauth.rate_limits;');
  await db.query('insert into auth.users(id,email,raw_user_meta_data) values ($1,$2,$3),($4,$5,$6)',
    [USER, 'player@example.com', { username: 'PlayerOne' }, OTHER, 'other@example.com', { username: 'PlayerTwo' }]);
  profile = (await db.query<Profile>('select * from cubauth.profiles where user_id=$1', [USER])).rows[0]!;
  other = (await db.query<Profile>('select * from cubauth.profiles where user_id=$1', [OTHER])).rows[0]!;
});
afterEach(() => { vi.restoreAllMocks(); });

describe('PostgreSQL migration and session rules', () => {
  it('creates permanent profiles and resolves usernames case-insensitively', async () => {
    expect(await rpc('cubauth_login_identity', { p_username: 'pLaYeRoNe' })).toEqual({ email: 'player@example.com', user_id: USER });
    expect(await rpc('cubauth_login_identity', { p_username: 'PLAYER@EXAMPLE.COM' })).toEqual({ email: 'player@example.com', user_id: USER });
    expect(await rpc('cubauth_profiles', { p_names: ['playerone', 'missing'] })).toEqual([{ id: profile.id.replaceAll('-', ''), name: 'PlayerOne' }]);
    await expect(db.query('insert into auth.users(id,email,raw_user_meta_data) values ($1,$2,$3)',
      [crypto.randomUUID(), 'duplicate@example.com', { username: 'playerone' }])).rejects.toThrow();
  });

  it('denies RPC access to anon/authenticated and permits only service_role', async () => {
    for (const role of ['anon', 'authenticated']) {
      await db.exec(`set role ${role}`);
      try { await expect(rpc('cubauth_profile', { p_id: profile.id })).rejects.toThrow(/permission denied/); }
      finally { await db.exec('reset role'); }
    }
    await db.exec('set role service_role');
    try { expect(await rpc<Profile>('cubauth_profile', { p_id: profile.id })).toMatchObject({ name: 'PlayerOne' }); }
    finally { await db.exec('reset role'); }
  });

  it('rotates once, rejects the wrong client and does not resurrect expired tokens', async () => {
    await issue();
    const hash = await sha256('a'.repeat(64));
    expect(await rpc('cubauth_refresh', { p_hash: hash, p_new_hash: 'b'.repeat(64), p_client: 'wrong', p_ttl: 3600 })).toBeNull();
    const result = await Promise.all(['b', 'c'].map(char => rpc('cubauth_refresh', {
      p_hash: hash, p_new_hash: char.repeat(64), p_client: 'launcher', p_ttl: 3600,
    })));
    expect(result.filter(Boolean)).toHaveLength(1);
    expect(await rpc('cubauth_session', { p_hash: hash })).toBeNull();
    await db.exec("update cubauth.sessions set expires_at = now() - interval '1 second'");
    expect(await rpc('cubauth_refresh', { p_hash: 'b'.repeat(64), p_new_hash: 'd'.repeat(64), p_client: null, p_ttl: 3600 })).toBeNull();
  });

  it('checks join ownership, serverId, IP, expiry and revocation', async () => {
    await issue();
    const hash = await sha256('a'.repeat(64));
    expect(await rpc('cubauth_join', { p_hash: hash, p_profile: other.id, p_server: 'server', p_ip: '127.0.0.1' })).toBe(false);
    expect(await rpc('cubauth_join', { p_hash: hash, p_profile: profile.id, p_server: 'server', p_ip: '::1' })).toBe(true);
    expect(await rpc('cubauth_has_joined', { p_name: 'PlayerOne', p_server: 'server', p_ip: '0:0:0:0:0:0:0:1' })).toMatchObject({ id: profile.id });
    expect(await rpc('cubauth_has_joined', { p_name: 'PlayerOne', p_server: 'server', p_ip: '127.0.0.1' })).toBeNull();
    expect(await rpc('cubauth_has_joined', { p_name: 'PlayerTwo', p_server: 'server' })).toBeNull();
    expect(await rpc('cubauth_has_joined', { p_name: 'PlayerOne', p_server: 'wrong' })).toBeNull();
    await db.exec("update cubauth.joins set expires_at=now()-interval '1 second'");
    expect(await rpc('cubauth_has_joined', { p_name: 'PlayerOne', p_server: 'server' })).toBeNull();
    await rpc('cubauth_join', { p_hash: hash, p_profile: profile.id, p_server: 'server', p_ip: '127.0.0.1' });
    await rpc('cubauth_invalidate', { p_hash: hash });
    expect(await rpc('cubauth_has_joined', { p_name: 'PlayerOne', p_server: 'server' })).toBeNull();
  });

  it('restricts skin updates to a live session for the owner', async () => {
    await issue();
    const args = { p_hash: await sha256('a'.repeat(64)), p_skin: 'f'.repeat(64), p_model: 'slim' };
    expect(await rpc('cubauth_set_skin', { ...args, p_profile: other.id })).toBe(false);
    expect(await rpc('cubauth_set_skin', { ...args, p_profile: profile.id })).toBe(true);
    expect(await rpc('cubauth_profile', { p_id: profile.id })).toMatchObject({ skin_model: 'slim', skin_hash: 'f'.repeat(64) });
    await rpc('cubauth_signout', { p_user_id: USER });
    expect(await rpc('cubauth_set_skin', { ...args, p_profile: profile.id })).toBe(false);
  });

  it('caps sessions, revokes on password change and honors bans', async () => {
    for (let i = 0; i < 12; i++) await issue(USER, String(i));
    expect((await db.query<{ count: number }>('select count(*)::int as count from cubauth.sessions')).rows[0]!.count).toBe(10);
    await db.query('update auth.users set encrypted_password=$1 where id=$2', ['new-password-hash', USER]);
    expect((await db.query('select * from cubauth.sessions')).rows).toHaveLength(0);
    await issue();
    await db.query("update auth.users set banned_until=now()+interval '1 hour' where id=$1", [USER]);
    expect(await rpc('cubauth_session', { p_hash: await sha256('a'.repeat(64)) })).toBeNull();
    expect(await issue(USER, 'new')).toBeNull();
  });

  it('counts limits atomically and cleanup removes only expired rows', async () => {
    const args = { p_key: 'test', p_limit: 2, p_window: 600 };
    expect(await rpc('cubauth_rate_limit', args)).toBe(true);
    expect(await rpc('cubauth_rate_limit', args)).toBe(true);
    expect(await rpc('cubauth_rate_limit', args)).toBe(false);
    await issue();
    await db.exec("update cubauth.rate_limits set expires_at=now()-interval '1 second'");
    expect(await rpc('cubauth_rate_limit', args)).toBe(true);
    await rpc('cubauth_cleanup');
    expect(await rpc('cubauth_session', { p_hash: await sha256('a'.repeat(64)) })).not.toBeNull();
  });
});

describe('HTTP protocol with real SQL RPCs and simulated Supabase Auth', () => {
  const call = (path: string, body?: unknown, method = body === undefined ? 'GET' : 'POST') => app.request(`https://auth.example.com${path}`, {
    method, headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.1' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }, env);

  beforeEach(() => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = new URL(String(input));
      expect(url.origin).toBe(env.SUPABASE_URL);
      if (url.pathname.startsWith('/rest/v1/rpc/')) {
        expect(new Headers(init?.headers).get('apikey')).toBe('sb_secret_test');
        const result = await rpc(url.pathname.split('/').at(-1)!, JSON.parse(String(init?.body)));
        return Response.json(result ?? null);
      }
      if (url.pathname === '/auth/v1/token') {
        const data = JSON.parse(String(init?.body));
        if (data.email !== 'player@example.com' || data.password !== 'correct-password') return Response.json({ error: 'invalid_credentials' }, { status: 400 });
        return Response.json({ user: { id: USER }, access_token: 'supabase-session' });
      }
      if (url.pathname === '/auth/v1/logout') return new Response(null, { status: 204 });
      throw new Error(`Unexpected external request: ${url.pathname}`);
    });
  });

  it('authenticates, validates, joins, signs the profile, refreshes and invalidates', async () => {
    const login = await call('/authserver/authenticate', { username: 'PlayerOne', password: 'correct-password', requestUser: true, clientToken: 'custom-client' });
    expect(login.status).toBe(200);
    const account = await login.json() as { accessToken: string; clientToken: string; selectedProfile: { id: string }; user: { id: string } };
    expect(account.clientToken).toBe('custom-client');
    expect(account.user.id).toBe(USER.replaceAll('-', ''));
    expect(account.accessToken).toMatch(/^[a-f0-9]{64}$/);
    expect((await call('/authserver/validate', { accessToken: account.accessToken })).status).toBe(204);
    expect((await call('/authserver/validate', { accessToken: account.accessToken, clientToken: 'wrong' })).status).toBe(403);
    expect((await call('/sessionserver/session/minecraft/join', { accessToken: account.accessToken, selectedProfile: account.selectedProfile.id, serverId: '-hash' })).status).toBe(204);
    const joined = await call('/sessionserver/session/minecraft/hasJoined?username=PlayerOne&serverId=-hash');
    expect(joined.status).toBe(200);
    expect(await joined.json()).toMatchObject({ id: account.selectedProfile.id, properties: [{ name: 'textures', signature: expect.any(String) }, { name: 'uploadableTextures', value: 'skin', signature: expect.any(String) }] });
    const refreshed = await call('/authserver/refresh', { accessToken: account.accessToken, clientToken: account.clientToken });
    expect(refreshed.status).toBe(200);
    const next = await refreshed.json() as { accessToken: string };
    expect((await call('/authserver/validate', { accessToken: account.accessToken })).status).toBe(403);
    expect((await call('/authserver/invalidate', { accessToken: next.accessToken })).status).toBe(204);
    expect((await call('/authserver/validate', { accessToken: next.accessToken })).status).toBe(403);
    expect((await call('/authserver/invalidate', { accessToken: 'already-gone' })).status).toBe(204);
  });

  it('returns identical errors for wrong passwords and nonexistent users', async () => {
    const bad = await call('/authserver/authenticate', { username: 'PlayerOne', password: 'bad' });
    const unknown = await call('/authserver/authenticate', { username: 'Nobody', password: 'bad' });
    expect(bad.status).toBe(403);
    expect(unknown.status).toBe(403);
    expect(await bad.json()).toEqual(await unknown.json());
  });

  it('rejects profile reassignment without invalidating the original session', async () => {
    await issue();
    const response = await call('/authserver/refresh', { accessToken: 'a'.repeat(64), selectedProfile: { id: other.id.replaceAll('-', ''), name: other.name } });
    expect(response.status).toBe(400);
    expect((await call('/authserver/validate', { accessToken: 'a'.repeat(64) })).status).toBe(204);
  });
});
