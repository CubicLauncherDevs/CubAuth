import { Hono } from 'hono';
import { decode } from 'fast-png';
import { rateLimit } from './auth';
import { base64, sha256 } from './crypto';
import { ApiError, badRequest } from './errors';
import { ImportReader, limitedImportBody, publicImportUrl } from './import-fetch';
import { MAX_SKIN_BYTES, sanitizeSkin } from './skins';
import { Supabase } from './supabase';
import type { Env } from './types';
import { ip, jsonBody, text } from './validation';

type Provider = 'authlib' | 'elyby' | 'battly';
interface Source { provider: Provider; identifier: string; serverUrl?: string }
interface Metadata { skinDomains: string[]; meta?: { serverName?: string } }
const noProfile = () => new ApiError(404, 'ImportProfileNotFound', 'The source profile was not found. Check the username or UUID.');
const noSkin = () => new ApiError(404, 'ImportSkinNotFound', 'The source profile does not have a public skin.');
const invalidProfile = () => new ApiError(422, 'ImportInvalidProfile', 'The source did not return a valid profile.');

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalidProfile();
  return value as Record<string, unknown>;
}
function compactId(value: unknown): string | null {
  if (typeof value !== 'string' || !/^(?:[a-f\d]{32}|[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12})$/i.test(value)) return null;
  return value.replaceAll('-', '').toLowerCase();
}
function baseUrl(value: string): URL {
  const url = publicImportUrl(value);
  if (url.search) throw badRequest('Use the root API URL without query parameters.');
  url.pathname = `${url.pathname.replace(/\/$/, '')}/`;
  return url;
}
function skinDomainAllowed(host: string, domains: string[]) {
  return [...domains, '.minecraft.net', '.mojang.com'].some(rule => {
    const domain = rule.toLowerCase();
    return domain.startsWith('.') ? host.endsWith(domain) : host === domain;
  });
}

async function discover(reader: ImportReader, value: string): Promise<{ base: URL; metadata: Metadata }> {
  let base = baseUrl(value);
  for (let hop = 0; hop < 3; hop++) {
    const { response, url } = await reader.response(base);
    if (!response.ok) throw new ApiError(502, 'ImportProviderRejected', `The Authlib API rejected the request (HTTP ${response.status}).`);
    const location = response.headers.get('X-Authlib-Injector-API-Location');
    if (location) {
      const next = baseUrl(new URL(location, url).href);
      if (next.href !== baseUrl(url.href).href) {
        await response.body?.cancel().catch(() => {});
        base = next;
        continue;
      }
    }
    const data = object(await reader.parseJson(response));
    if (!Array.isArray(data.skinDomains) || data.skinDomains.length > 100
      || data.skinDomains.some(domain => typeof domain !== 'string' || domain.length > 255)) throw invalidProfile();
    return { base: baseUrl(url.href), metadata: data as unknown as Metadata };
  }
  throw new ApiError(422, 'ImportTooManyRedirects', 'The Authlib API discovery did not finish.');
}

async function yggdrasil(reader: ImportReader, source: Source) {
  const { base, metadata } = await discover(reader, source.provider === 'elyby'
    ? 'https://account.ely.by/api/authlib-injector/' : source.serverUrl!);
  let id = compactId(source.identifier);
  if (!id) {
    const profiles = await reader.json(new URL('api/profiles/minecraft', base), { method: 'POST', body: JSON.stringify([source.identifier]) });
    if (!Array.isArray(profiles)) { if (profiles === null) throw noProfile(); throw invalidProfile(); }
    const found = profiles.find(value => value && typeof value === 'object'
      && typeof value.name === 'string' && value.name.toLowerCase() === source.identifier.toLowerCase());
    if (!found) throw noProfile();
    id = compactId(found.id);
    if (!id) throw invalidProfile();
  }
  const result = await reader.json(new URL(`sessionserver/session/minecraft/profile/${id}?unsigned=true`, base));
  if (!result) throw noProfile();
  const profile = object(result);
  if (compactId(profile.id) !== id || typeof profile.name !== 'string' || !/^[A-Za-z0-9_]{1,64}$/.test(profile.name)
    || !Array.isArray(profile.properties)) throw invalidProfile();
  const property = profile.properties.find(value => value && typeof value === 'object' && value.name === 'textures');
  if (!property) throw noSkin();
  let payload: Record<string, unknown>;
  try {
    if (typeof property.value !== 'string') throw invalidProfile();
    payload = object(JSON.parse(atob(property.value)));
  } catch { throw invalidProfile(); }
  if (payload.profileId !== undefined && compactId(payload.profileId) !== id) throw invalidProfile();
  const textures = object(payload.textures);
  if (!textures.SKIN) throw noSkin();
  const skin = object(textures.SKIN);
  if (typeof skin.url !== 'string') throw invalidProfile();
  const skinUrl = publicImportUrl(skin.url, true);
  if (!skinDomainAllowed(skinUrl.hostname, metadata.skinDomains)) throw new ApiError(422, 'ImportSkinDomainMismatch', 'The texture host is not declared by the source Authlib service.');
  const model = skin.metadata && object(skin.metadata).model === 'slim' ? 'slim' : 'default';
  const { response } = await reader.response(skinUrl, { allowedHost: host => skinDomainAllowed(host, metadata.skinDomains) });
  if (response.status === 404 || response.status === 204) throw noSkin();
  if (!response.ok) throw new ApiError(502, 'ImportProviderRejected', `The source rejected the skin download (HTTP ${response.status}).`);
  return { sourceName: profile.name, sourceUuid: id, serverUrl: base.href, model,
    png: await limitedImportBody(response, MAX_SKIN_BYTES), modelDetected: false } as const;
}

function detectModel(png: Uint8Array): 'default' | 'slim' {
  const image = decode(png);
  if (image.height === 32) return 'default';
  // Slim-arm unused rectangles in the standard 64x64 UV layout.
  const areas = [[50, 16, 2, 4], [54, 20, 2, 12], [42, 48, 2, 4], [46, 52, 2, 12]] as const;
  let transparent = false, black = true, white = true;
  for (const [x, y, w, h] of areas) for (let row = y; row < y + h; row++) for (let col = x; col < x + w; col++) {
    const offset = (row * 64 + col) * 4;
    const [r, g, b, a] = image.data.slice(offset, offset + 4);
    if (a !== 255) transparent = true;
    if (r !== 0 || g !== 0 || b !== 0 || a !== 255) black = false;
    if (r !== 255 || g !== 255 || b !== 255 || a !== 255) white = false;
  }
  return transparent || black || white ? 'slim' : 'default';
}

export async function resolveImport(source: Source) {
  const reader = new ImportReader();
  try {
    if (source.provider === 'battly') {
      let png: Uint8Array | undefined;
      for (const prefix of ['/api/skin/', '/api/v2/skin/']) {
        const { response } = await reader.response(`https://api.battlylauncher.com${prefix}${encodeURIComponent(source.identifier)}.png`);
        if (response.status === 404 || response.status === 204) { await response.body?.cancel().catch(() => {}); continue; }
        if (!response.ok) throw new ApiError(502, 'ImportProviderRejected', `Battly rejected the skin request (HTTP ${response.status}).`);
        png = await sanitizeSkin(await limitedImportBody(response, MAX_SKIN_BYTES), 'default');
        break;
      }
      if (!png) throw noSkin();
      return { provider: source.provider, sourceName: source.identifier, sourceUuid: null,
        serverUrl: 'https://api.battlylauncher.com/', model: detectModel(png), modelDetected: true,
        height: decode(png).height, skinDataUrl: `data:image/png;base64,${base64(png)}`, skinHash: await sha256(png) };
    }
    const result = await yggdrasil(reader, source);
    const png = await sanitizeSkin(result.png, result.model);
    return { provider: source.provider, sourceName: result.sourceName, sourceUuid: result.sourceUuid,
      serverUrl: result.serverUrl, model: result.model, modelDetected: false,
      height: decode(png).height, skinDataUrl: `data:image/png;base64,${base64(png)}`, skinHash: await sha256(png) };
  } catch (error) {
    if (error instanceof ApiError) {
      if (error.code === 'IllegalArgumentException') throw new ApiError(422, 'ImportInvalidSkin', 'The source skin is not a supported PNG. Use a 64x64 or 64x32 skin up to 128 KiB.');
      throw error;
    }
    throw new ApiError(502, 'ImportProviderUnavailable', 'The source service did not respond correctly. Try again later.');
  }
}

export const importRoutes = new Hono<{ Bindings: Env }>();
importRoutes.post('/preview', async c => {
  const body = await jsonBody(c.req.raw);
  if (!['authlib', 'elyby', 'battly'].includes(String(body.provider))) throw badRequest('Choose Authlib, Ely.by or Battly.');
  const provider = body.provider as Provider, identifier = text(body.identifier, 'source username or UUID', 64).trim();
  if (!/^[A-Za-z0-9_]{1,64}$/.test(identifier) && !compactId(identifier)) throw badRequest('Use a username or UUID.');
  if (provider === 'battly' && (!/^[A-Za-z0-9_]{1,16}$/.test(identifier) || compactId(identifier))) throw badRequest('Battly imports use a username, not a UUID.');
  const serverUrl = provider === 'authlib' ? baseUrl(text(body.serverUrl, 'Authlib server URL', 2048)).href : undefined;
  await rateLimit(new Supabase(c.env), 'import-preview-ip', ip(c.req.header('CF-Connecting-IP') ?? '127.0.0.1'), 20, 600);
  return c.json(await resolveImport({ provider, identifier, serverUrl }));
});
