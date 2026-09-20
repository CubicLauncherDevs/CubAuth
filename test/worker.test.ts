import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { env as workerEnv } from 'cloudflare:test';
import { encode, decode } from 'fast-png';
import { app } from '../src/index';
import { base64, bytes, sha256 } from '../src/crypto';
import { fullProfile } from '../src/profiles';
import { sanitizeSkin } from '../src/skins';
import type { Env, Profile } from '../src/types';

let env: Env;
let publicKey: CryptoKey;
const profile: Profile = { id: '00000000-0000-4000-8000-000000000001', user_id: '00000000-0000-4000-8000-000000000002', name: 'PlayerOne', skin_model: 'slim', skin_hash: 'f'.repeat(64) };
const skin = (height = 64) => encode({ width: 64, height, data: new Uint8Array(64 * height * 4).fill(128), text: { note: 'discard me' } });

beforeAll(async () => {
  const pair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) }, true, ['sign', 'verify']) as CryptoKeyPair;
  publicKey = pair.publicKey;
  env = { ...workerEnv,
    PUBLIC_URL: 'https://auth.example.com', SUPABASE_URL: 'https://test.supabase.co', SERVER_NAME: 'CubAuth test',
    ALLOW_REGISTRATION: 'true', TOKEN_TTL_SECONDS: '1296000',
    SUPABASE_ANON_KEY: 'sb_publishable_test', SUPABASE_SERVICE_ROLE_KEY: 'sb_secret_test',
    SIGNING_PUBLIC_KEY: `-----BEGIN PUBLIC KEY-----\n${base64(new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey) as ArrayBuffer))}\n-----END PUBLIC KEY-----`,
    SIGNING_PRIVATE_KEY: `-----BEGIN PRIVATE KEY-----\n${base64(new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey) as ArrayBuffer))}\n-----END PRIVATE KEY-----`,
  } as Env;
});
afterEach(() => { vi.restoreAllMocks(); });

describe('real Workers crypto and PNG processing', () => {
  it('signs the exact base64 property with RSA-SHA1 and advertises the skin domain', async () => {
    const result = await fullProfile(profile, env, true);
    for (const property of result.properties) {
      const signature = Uint8Array.from(atob(property.signature!), c => c.charCodeAt(0));
      expect(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, signature, bytes(property.value))).toBe(true);
      expect(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, signature, bytes(property.value + 'x'))).toBe(false);
    }
    expect(JSON.parse(atob(result.properties[0]!.value)).textures.SKIN).toEqual({
      url: `https://test.supabase.co/storage/v1/object/public/skins/${'f'.repeat(64)}`, metadata: { model: 'slim' },
    });
    const metadata = await app.request('https://auth.example.com/', {}, env);
    expect(await metadata.json()).toMatchObject({ skinDomains: ['test.supabase.co'], signaturePublickey: env.SIGNING_PUBLIC_KEY });
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
    const input = encode({ width: 64, height: 64, channels: 1, depth: 8,
      data: new Uint8Array(4096).fill(1), palette: [[100, 200, 50, 0], [1, 2, 3, 255]] });
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
    const corrupt = skin(); corrupt[corrupt.length - 1] = corrupt[corrupt.length - 1]! ^ 1;
    const interlaced = encode({ width: 64, height: 64, data: new Uint8Array(64 * 64 * 4) }, { interlace: 'Adam7' });
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

describe('Workers HTTP routes', () => {
  it('serves the panel with CSP and API discovery', async () => {
    const response = await app.request('https://auth.example.com/account', {}, env);
    expect(response.status).toBe(200);
    expect(await response.text()).toContain('Tu cuenta. Tu skin. Tu mundo.');
    expect(response.headers.get('Content-Security-Policy')).toContain("script-src 'self'");
    expect(response.headers.get('X-Authlib-Injector-API-Location')).toBe('https://auth.example.com/');
  });

  it('returns JSON errors for unknown routes and malformed/oversized requests', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => { throw new Error('No network expected'); });
    const unknown = await app.request('https://auth.example.com/missing', {}, env);
    expect(unknown.status).toBe(404);
    expect(await unknown.json()).toMatchObject({ error: 'NotFound' });
    for (const [body, status] of [['{', 400], ['a'.repeat(17000), 413]] as const) {
      const response = await app.request('https://auth.example.com/authserver/authenticate', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
      }, env);
      expect(response.status).toBe(status);
    }
  });

  it('allows registration from the Worker origin even with the default PUBLIC_URL', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
      const url = new URL(String(input));
      if (url.pathname.endsWith('/cubauth_rate_limit')) return Response.json(true);
      if (url.pathname === '/auth/v1/signup') return Response.json({ user: { id: profile.user_id } });
      throw new Error(`Unexpected fetch: ${url.pathname}`);
    });
    const response = await app.request('https://cubauth.example.workers.dev/account/register', {
      method: 'POST',
      headers: { Origin: 'https://cubauth.example.workers.dev', 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'player@example.com', username: 'PlayerOne', password: 'test-password-only' }),
    }, { ...env, PUBLIC_URL: 'http://localhost:8787' });
    expect(response.status).toBe(202);
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it.each(['https://evil.example', 'http://localhost:8787', 'null'])('rejects a foreign browser origin (%s) before touching Supabase', async origin => {
    const spy = vi.spyOn(globalThis, 'fetch');
    const response = await app.request('https://auth.example.com/authserver/invalidate', {
      method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' }, body: '{}',
    }, { ...env, PUBLIC_URL: 'http://localhost:8787' });
    expect(response.status).toBe(403);
    expect(spy).not.toHaveBeenCalled();
  });

  it('stores a sanitized skin by hash and updates only the authenticated profile', async () => {
    let stored: Uint8Array | undefined;
    let update: Record<string, unknown> | undefined;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = new URL(String(input));
      if (url.pathname.endsWith('/cubauth_session')) return Response.json({ user_id: profile.user_id, client_token: 'test', profile });
      if (url.pathname.endsWith('/cubauth_rate_limit')) return Response.json(true);
      if (url.pathname.startsWith('/storage/v1/object/skins/')) {
        stored = init!.body as Uint8Array;
        expect(url.pathname.split('/').at(-1)).toBe(await sha256(stored));
        expect(new Headers(init!.headers).get('Content-Type')).toBe('image/png');
        return Response.json({ Key: 'ok' });
      }
      if (url.pathname.endsWith('/cubauth_set_skin')) { update = JSON.parse(String(init!.body)); return Response.json(true); }
      throw new Error(`Unexpected fetch: ${url.pathname}`);
    });
    const form = new FormData();
    form.set('model', 'slim'); form.set('file', new Blob([skin()], { type: 'image/png' }), 'skin.png');
    const response = await app.request(`https://auth.example.com/api/user/profile/${profile.id.replaceAll('-', '')}/skin`, {
      method: 'PUT', headers: { Authorization: `Bearer ${'a'.repeat(64)}` }, body: form,
    }, env);
    expect(response.status).toBe(204);
    expect(decode(stored!).text).toEqual({});
    expect(update).toMatchObject({ p_profile: profile.id, p_model: 'slim', p_skin: await sha256(stored!) });
  });

  it('rejects skin upload for another profile before uploading a file', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json({ user_id: profile.user_id, client_token: 'test', profile }));
    const response = await app.request('https://auth.example.com/api/user/profile/11111111111141118111111111111111/skin', {
      method: 'PUT', headers: { Authorization: `Bearer ${'a'.repeat(64)}` },
    }, env);
    expect(response.status).toBe(403);
    expect(spy).toHaveBeenCalledTimes(1);
  });
});
