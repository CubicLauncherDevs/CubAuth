import { afterEach, beforeEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { env as workerEnv, applyD1Migrations, type D1Migration } from 'cloudflare:test';
import { Database } from '../src/database';
import { newToken } from '../src/crypto';
import { encode, decode } from 'fast-png';
import { app } from '../src/index';
import { base64, bytes, sha256 } from '../src/crypto';
import { fullProfile } from '../src/profiles';
import { sanitizeSkin } from '../src/skins';
import type { Env, Profile } from '../src/types';

let env: Env;
let publicKey: CryptoKey;
const profile: Profile = {
  id: '00000000-0000-4000-8000-000000000001',
  user_id: '00000000-0000-4000-8000-000000000002',
  name: 'PlayerOne',
  skin_model: 'slim',
  skin_hash: 'f'.repeat(64),
};
const skin = (height = 64) =>
  encode({
    width: 64,
    height,
    data: new Uint8Array(64 * height * 4).fill(128),
    text: { note: 'discard me' },
  });

beforeAll(async () => {
  const pair = (await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-1',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
    },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  publicKey = pair.publicKey;
  env = {
    ...workerEnv,
    PUBLIC_URL: 'https://auth.example.com',
    SERVER_NAME: 'CubAuth test',
    ALLOW_REGISTRATION: 'true',
    TOKEN_TTL_SECONDS: '1296000',
    ACCOUNT_URL: 'https://accounts.example.com',
    WEB_ORIGINS: 'https://accounts.example.com',
    DISCORD_CLIENT_ID: '111',
    DISCORD_CLIENT_SECRET: 'secret',
    SIGNING_PUBLIC_KEY: `-----BEGIN PUBLIC KEY-----\n${base64(new Uint8Array((await crypto.subtle.exportKey('spki', pair.publicKey)) as ArrayBuffer))}\n-----END PUBLIC KEY-----`,
    SIGNING_PRIVATE_KEY: `-----BEGIN PRIVATE KEY-----\n${base64(new Uint8Array((await crypto.subtle.exportKey('pkcs8', pair.privateKey)) as ArrayBuffer))}\n-----END PRIVATE KEY-----`,
  } as Env;
  await applyD1Migrations(
    env.DB,
    (workerEnv as unknown as { TEST_MIGRATIONS: D1Migration[] }).TEST_MIGRATIONS,
  );
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe('real Workers crypto and PNG processing', () => {
  it('signs the exact base64 property with RSA-SHA1 and advertises the skin domain', async () => {
    const result = await fullProfile(profile, env, true);
    for (const property of result.properties) {
      const signature = Uint8Array.from(atob(property.signature!), (c) => c.charCodeAt(0));
      expect(
        await crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, signature, bytes(property.value)),
      ).toBe(true);
      expect(
        await crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, signature, bytes(property.value + 'x')),
      ).toBe(false);
    }
    expect(JSON.parse(atob(result.properties[0]!.value)).textures.SKIN).toEqual({
      url: `https://auth.example.com/textures/${'f'.repeat(64)}`,
      metadata: { model: 'slim' },
    });
    const metadata = await app.request('https://auth.example.com/', {}, env);
    expect(await metadata.json()).toMatchObject({
      skinDomains: ['auth.example.com'],
      signaturePublickey: env.SIGNING_PUBLIC_KEY,
    });
  });

  it('strips PNG metadata and preserves bitmap and alpha', async () => {
    const original = skin();
    const clean = await sanitizeSkin(original, 'slim');
    const decoded = decode(clean, { checkCrc: true });
    expect(decoded.text).toEqual({});
    expect(decoded.data).toEqual(decode(original).data);
    expect(await sha256(clean)).toBe(await sha256(await sanitizeSkin(clean, 'slim')));
  });

  it('preserves indexed transparency when normalizing to RGBA', async () => {
    const input = encode({
      width: 64,
      height: 64,
      channels: 1,
      depth: 8,
      data: new Uint8Array(4096).fill(1),
      palette: [
        [100, 200, 50, 0],
        [1, 2, 3, 255],
      ],
    });
    const output = decode(await sanitizeSkin(input, 'default'));
    expect(output.channels).toBe(4);
    expect(Array.from(output.data.slice(0, 4))).toEqual([1, 2, 3, 255]);
  });

  it('supports legacy skins only with the classic model', async () => {
    expect(decode(await sanitizeSkin(skin(32), 'default')).height).toBe(32);
    await expect(sanitizeSkin(skin(32), 'slim')).rejects.toThrow('Invalid skin');
  });

  it('rejects oversized dimensions, truncation, bad CRC and interlaced PNG', async () => {
    const large = encode({ width: 128, height: 64, data: new Uint8Array(128 * 64 * 4) });
    const corrupt = skin();
    corrupt[corrupt.length - 1] = corrupt[corrupt.length - 1]! ^ 1;
    const interlaced = encode(
      { width: 64, height: 64, data: new Uint8Array(64 * 64 * 4) },
      { interlace: 'Adam7' },
    );
    for (const file of [large, skin().slice(0, 40), corrupt, new Uint8Array(131073), interlaced]) {
      await expect(sanitizeSkin(file, 'default')).rejects.toThrow('Invalid skin');
    }
  });

  it('rejects a small IHDR with oversized compressed pixel data before PNG decode', async () => {
    // The compressed stream belongs to 64x128; change just IHDR to declare 64x64.
    const bomb = encode({ width: 64, height: 128, data: new Uint8Array(64 * 128 * 4) });
    new DataView(bomb.buffer, bomb.byteOffset, bomb.byteLength).setUint32(20, 64);
    await expect(sanitizeSkin(bomb, 'default')).rejects.toThrow('Invalid skin');
  });
});

const post = (path: string, body: unknown, token?: string) =>
  app.request(
    'https://auth.example.com' + path,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) },
      body: JSON.stringify(body),
    },
    env,
  );

describe('Discord, D1, R2 and Yggdrasil HTTP flow', () => {
  beforeEach(async () => {
    await env.DB.batch(
      [
        'name_history',
        'joins',
        'sessions',
        'launcher_tokens',
        'profiles',
        'accounts',
        'oauth_states',
        'login_tickets',
        'registrations',
        'legacy_tickets',
        'rate_limits',
      ].map((table) => env.DB.prepare('DELETE FROM ' + table)),
    );
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = new URL(String(input)).pathname;
      if (path.endsWith('/oauth2/token')) return Response.json({ access_token: 'discord-access' });
      if (path.endsWith('/users/@me')) return Response.json({ id: '333' });
      throw new Error('Unexpected external request');
    });
  });

  async function oauth() {
    const verifier = newToken();
    const start = await post('/discord/start', { challenge: await sha256(verifier) });
    expect(start.status).toBe(200);
    const state = new URL(((await start.json()) as { url: string }).url).searchParams.get('state')!;
    const response = await app.request(
      'https://auth.example.com/discord/callback?' + new URLSearchParams({ code: 'discord-code', state }),
      {},
      env,
    );
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get('Location')!);
    const code = new URLSearchParams(location.hash.slice(1)).get('code')!;
    expect(code).toMatch(/^[a-f0-9]{64}$/);
    return { code, verifier, state };
  }
  async function register() {
    const pending = await oauth();
    const exchange = await post('/discord/exchange', pending);
    const { registrationToken } = (await exchange.json()) as { registrationToken: string };
    const registered = await post('/discord/register', { registrationToken, username: 'PlayerOne' });
    expect(registered.status).toBe(200);
    return (
      (await registered.json()) as {
        session: { accessToken: string; clientToken: string; selectedProfile: { id: string; name: string } };
      }
    ).session;
  }
  it('completes OAuth, registration, web login, one-use token and launcher lifecycle', async () => {
    const web = await register();
    expect((await post('/account/session/validate', web)).status).toBe(204);
    expect((await post('/authserver/validate', web)).status).toBe(403);
    const issued = await post('/account/launcher-token', {}, web.accessToken);
    expect(issued.status).toBe(200);
    const { token } = (await issued.json()) as { token: string };
    const login = await post('/authserver/authenticate', {
      username: 'PlayerOne',
      password: token,
      clientToken: 'client',
      requestUser: true,
    });
    expect(login.status).toBe(200);
    const launcher = (await login.json()) as {
      accessToken: string;
      selectedProfile: { id: string };
      user: { id: string };
    };
    expect(launcher.user.id).toMatch(/^[a-f0-9]{32}$/);
    expect((await post('/authserver/authenticate', { username: 'PlayerOne', password: token })).status).toBe(
      403,
    );
    expect((await post('/account/launcher-token', {}, launcher.accessToken)).status).toBe(401);
    expect(
      (
        await post('/sessionserver/session/minecraft/join', {
          accessToken: launcher.accessToken,
          selectedProfile: launcher.selectedProfile.id,
          serverId: 'server',
        })
      ).status,
    ).toBe(204);
    const joined = await app.request(
      'https://auth.example.com/sessionserver/session/minecraft/hasJoined?username=PlayerOne&serverId=server',
      {},
      env,
    );
    expect(joined.status).toBe(200);
    const rotated = await post('/authserver/refresh', {
      accessToken: launcher.accessToken,
      clientToken: 'client',
    });
    expect(rotated.status).toBe(200);
    expect((await post('/authserver/validate', launcher)).status).toBe(403);
    expect((await post('/account/signout-all', {}, web.accessToken)).status).toBe(204);
    expect((await post('/account/session/validate', web)).status).toBe(401);
    expect((await post('/authserver/validate', await rotated.json())).status).toBe(403);
  });
  it('keeps the web session in an HttpOnly cookie, rotates it and clears it on logout', async () => {
    await register();
    const login = await post('/discord/exchange', await oauth());
    expect(login.status).toBe(200);
    const raw = login.headers.get('set-cookie')!;
    expect(raw).toContain('cubauth_session=');
    expect(raw).toContain('HttpOnly');
    expect(raw).toContain('SameSite=Lax');
    expect(raw).toContain('Path=/');
    expect(raw).toContain('Secure');
    const cookie = raw.split(';')[0]!;
    const me = (headers: Record<string, string>) =>
      app.request('https://auth.example.com/account/me', { headers }, env);
    expect((await me({ Cookie: cookie })).status).toBe(200);
    const restored = await app.request(
      'https://auth.example.com/account/session',
      { headers: { Cookie: cookie } },
      env,
    );
    expect(restored.status).toBe(200);
    expect(await restored.json()).toMatchObject({
      accessToken: cookie.split('=')[1],
      selectedProfile: { name: 'PlayerOne' },
    });
    expect((await app.request('https://auth.example.com/account/session', {}, env)).status).toBe(401);
    const refreshed = await app.request(
      'https://auth.example.com/account/session/refresh',
      { method: 'POST', headers: { Cookie: cookie, 'Content-Type': 'application/json' }, body: '{}' },
      env,
    );
    expect(refreshed.status).toBe(200);
    const rotated = refreshed.headers.get('set-cookie')!.split(';')[0]!;
    expect(rotated).not.toBe(cookie);
    expect((await me({ Cookie: cookie })).status).toBe(401);
    expect((await me({ Cookie: rotated })).status).toBe(200);
    const loggedOut = await app.request(
      'https://auth.example.com/account/session/logout',
      { method: 'POST', headers: { Cookie: rotated, 'Content-Type': 'application/json' }, body: '{}' },
      env,
    );
    expect(loggedOut.status).toBe(204);
    expect(loggedOut.headers.get('set-cookie')).toContain('Max-Age=0');
    expect((await me({ Cookie: rotated })).status).toBe(401);
  });
  it('deletes the account only with the exact Minecraft name and clears its data', async () => {
    const web = await register();
    const issued = await post('/account/launcher-token', {}, web.accessToken);
    const { token } = (await issued.json()) as { token: string };
    const remove = (confirmation: string) =>
      app.request(
        'https://auth.example.com/account',
        {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + web.accessToken },
          body: JSON.stringify({ confirmation }),
        },
        env,
      );
    expect((await remove('playerone')).status).toBe(400);
    expect((await post('/account/session/validate', web)).status).toBe(204);
    const deleted = await remove('PlayerOne');
    expect(deleted.status).toBe(204);
    expect(deleted.headers.get('set-cookie')).toContain('Max-Age=0');
    expect((await post('/account/session/validate', web)).status).toBe(401);
    expect(
      (
        await app.request(
          'https://auth.example.com/sessionserver/session/minecraft/profile/' + web.selectedProfile.id,
          {},
          env,
        )
      ).status,
    ).toBe(204);
    expect(
      (await post('/authserver/authenticate', { username: 'PlayerOne', password: token })).status,
    ).toBe(403);
    const again = await register();
    expect(again.selectedProfile.name).toBe('PlayerOne');
    expect(again.selectedProfile.id).not.toBe(web.selectedProfile.id);
  });
  it('binds OAuth tickets to the initiating tab and consumes state and tickets once', async () => {
    const pending = await oauth();
    expect((await post('/discord/exchange', { ...pending, verifier: newToken() })).status).toBe(403);
    expect((await post('/discord/exchange', pending)).status).toBe(200);
    expect((await post('/discord/exchange', pending)).status).toBe(403);
    const replay = await app.request(
      'https://auth.example.com/discord/callback?' +
        new URLSearchParams({ code: 'code', state: pending.state }),
      {},
      env,
    );
    expect(replay.headers.get('Location')).toContain('error=DiscordStateExpired');
    const invalid = await app.request(
      'https://auth.example.com/discord/callback?code=code&state=bad',
      {},
      env,
    );
    expect(invalid.headers.get('Location')).not.toContain('#code=');
  });
  it('rejects failed Discord authorization and leaves email login disabled', async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(null, { status: 403 }));
    const verifier = newToken();
    const start = await post('/discord/start', { challenge: await sha256(verifier) });
    const state = new URL(((await start.json()) as { url: string }).url).searchParams.get('state')!;
    const callback = await app.request(
      'https://auth.example.com/discord/callback?' + new URLSearchParams({ code: 'code', state }),
      {},
      env,
    );
    expect(callback.headers.get('Location')).toContain('#error=');
    expect(
      (await post('/account/register', { email: 'old@example.com', password: 'old-password' })).status,
    ).toBe(410);
    expect(
      (await post('/authserver/authenticate', { username: 'OldPlayer', password: 'old-password' })).status,
    ).toBe(403);
    expect((await post('/account/password', {})).status).toBe(404);
  });
  it('uploads sanitized skins to R2, serves textures and rejects other-profile writes', async () => {
    const web = await register();
    const form = new FormData();
    form.set('file', new Blob([skin()]), 'skin.png');
    form.set('model', 'slim');
    const upload = await app.request(
      'https://auth.example.com/api/user/profile/' + web.selectedProfile.id + '/skin',
      { method: 'PUT', headers: { Authorization: 'Bearer ' + web.accessToken }, body: form },
      env,
    );
    expect(upload.status).toBe(204);
    const current = await new Database(env).profileForDiscord('333');
    const texture = await app.request('https://auth.example.com/textures/' + current!.skin_hash, {}, env);
    expect(texture.status).toBe(200);
    expect(texture.headers.get('Content-Type')).toBe('image/png');
    expect(decode(new Uint8Array(await texture.arrayBuffer())).text).toEqual({});
    const denied = await app.request(
      'https://auth.example.com/api/user/profile/' + 'f'.repeat(32) + '/skin',
      { method: 'DELETE', headers: { Authorization: 'Bearer ' + web.accessToken } },
      env,
    );
    expect(denied.status).toBe(403);
  });
  it('renames without a password and preserves UUID and name history', async () => {
    const web = await register();
    const response = await post('/account/username', { username: 'NewPlayer' }, web.accessToken);
    expect(response.status).toBe(200);
    const next = ((await response.json()) as { session: typeof web }).session;
    expect(next.selectedProfile.id).toBe(web.selectedProfile.id);
    expect(next.selectedProfile.name).toBe('NewPlayer');
    expect((await post('/account/session/validate', web)).status).toBe(401);
    const details = await app.request(
      'https://auth.example.com/account/me',
      { headers: { Authorization: 'Bearer ' + next.accessToken } },
      env,
    );
    expect(await details.json()).toMatchObject({
      discordId: '333',
      nameHistory: [{ previousName: 'PlayerOne', newName: 'NewPlayer' }],
    });
  });
  it('migrates a legacy Supabase account, keeping its UUID, profile, skin and history', async () => {
    env.SUPABASE_URL = 'https://project.supabase.co';
    env.SUPABASE_ANON_KEY = 'anon-key';
    env.SUPABASE_SERVICE_ROLE_KEY = 'service-key';
    const legacySkin = skin();
    const legacySkinHash = await sha256(legacySkin);
    const profileId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
    vi.mocked(fetch).mockImplementation(async (input) => {
      const path = new URL(String(input)).pathname;
      if (path.endsWith('/oauth2/token')) return Response.json({ access_token: 'discord-access' });
      if (path.endsWith('/users/@me'))
        return Response.json({ id: '333', email: 'player@example.com' });
      if (path === '/rest/v1/rpc/cubauth_login_identity')
        return Response.json({ email: 'old@example.com', user_id: 'legacy-user' });
      if (path === '/auth/v1/token') return Response.json({ user: { id: 'legacy-user' }, access_token: 'legacy-access' });
      if (path === '/auth/v1/logout') return new Response(null, { status: 204 });
      if (path === '/rest/v1/rpc/cubauth_issue_session')
        return Response.json({ user_id: 'legacy-user' });
      if (path === '/rest/v1/rpc/cubauth_account')
        return Response.json({
          profile: {
            id: profileId,
            user_id: 'legacy-user',
            name: 'OldPlayer',
            skin_hash: legacySkinHash,
            skin_model: 'slim',
          },
          created_at: '2024-01-02T03:04:05Z',
          name_history: [
            { previous_name: 'First', new_name: 'OldPlayer', changed_at: '2024-01-01T00:00:00Z' },
          ],
          history_total: 1,
        });
      if (path === '/rest/v1/rpc/cubauth_invalidate') return Response.json(null);
      if (path === `/storage/v1/object/public/skins/${legacySkinHash}`)
        return new Response(legacySkin, { headers: { 'Content-Type': 'image/png' } });
      throw new Error('Unexpected external request: ' + path);
    });
    await register(); // The Discord account already exists and must be replaced.
    const verify = await post('/migration/verify', {
      identifier: 'OldPlayer',
      password: 'old-password',
    });
    expect(verify.status).toBe(200);
    const { token } = (await verify.json()) as { token: string };
    const pending = await oauth();
    const exchange = await post('/discord/exchange', { ...pending, migrationToken: token });
    expect(exchange.status).toBe(200);
    const session = (
      (await exchange.json()) as {
        session: { accessToken: string; selectedProfile: { id: string; name: string } };
      }
    ).session;
    expect(session.selectedProfile).toEqual({
      id: profileId.replace(/-/g, ''),
      name: 'OldPlayer',
    });
    const details = await app.request(
      'https://auth.example.com/account/me',
      { headers: { Authorization: 'Bearer ' + session.accessToken } },
      env,
    );
    expect(await details.json()).toMatchObject({
      discordId: '333',
      discordEmail: 'player@example.com',
      createdAt: '2024-01-02T03:04:05.000Z',
      nameHistory: [{ previousName: 'First', newName: 'OldPlayer' }],
      historyTotal: 1,
    });
    expect(
      await env.DB.prepare(
        "SELECT id, legacy_user_id, discord_email FROM accounts WHERE discord_id = '333'",
      ).first(),
    ).toEqual({ id: profileId, legacy_user_id: 'legacy-user', discord_email: 'player@example.com' });
    const texture = await app.request('https://auth.example.com/textures/' + legacySkinHash, {}, env);
    expect(texture.status).toBe(200);
    expect(
      (await env.DB.prepare('SELECT count(*) AS n FROM legacy_tickets').first<{ n: number }>())!.n,
    ).toBe(0);
  });
  it('rejects invalid legacy credentials without creating a migration ticket', async () => {
    env.SUPABASE_URL = 'https://project.supabase.co';
    env.SUPABASE_ANON_KEY = 'anon-key';
    env.SUPABASE_SERVICE_ROLE_KEY = 'service-key';
    vi.mocked(fetch).mockImplementation(async (input) => {
      const path = new URL(String(input)).pathname;
      if (path === '/rest/v1/rpc/cubauth_login_identity') return Response.json(null);
      if (path === '/auth/v1/token')
        return Response.json({ error_code: 'invalid_grant' }, { status: 400 });
      throw new Error('Unexpected external request: ' + path);
    });
    const verify = await post('/migration/verify', { identifier: 'Ghost', password: 'wrong' });
    expect(verify.status).toBe(403);
    expect(await verify.json()).toMatchObject({ error: 'MigrationCredentialsInvalid' });
    expect(
      (await env.DB.prepare('SELECT count(*) AS n FROM legacy_tickets').first<{ n: number }>())!.n,
    ).toBe(0);
  });
  it('enforces CORS, rejects oversized payloads and advertises the frontend', async () => {    const denied = await app.request(
      'https://auth.example.com/discord/start',
      {
        method: 'POST',
        headers: { Origin: 'https://evil.example', 'Content-Type': 'application/json' },
        body: '{}',
      },
      env,
    );
    expect(denied.status).toBe(403);
    const preflight = await app.request(
      'https://auth.example.com/account/launcher-token',
      {
        method: 'OPTIONS',
        headers: {
          Origin: 'https://accounts.example.com',
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'authorization,content-type',
        },
      },
      env,
    );
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get('Access-Control-Allow-Origin')).toBe('https://accounts.example.com');
    expect(preflight.headers.get('Access-Control-Allow-Credentials')).toBe('true');
    expect((await post('/discord/start', { challenge: 'x'.repeat(18000) })).status).toBe(413);
    const panel = await app.request('https://auth.example.com/account', {}, env);
    expect(panel.headers.get('Location')).toBe('https://accounts.example.com/account');
  });
});
