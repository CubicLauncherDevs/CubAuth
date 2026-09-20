import { isIP } from 'node:net';
import ipaddr from 'ipaddr.js';
import { ApiError } from './errors';

const failure = () => new ApiError(502, 'ImportProviderUnavailable', 'The source service could not be reached. Try again later.');
const forbidden = () => new ApiError(400, 'ImportAddressNotAllowed', 'Use a public HTTPS service on port 443, without credentials or a fragment.');

export function publicImportUrl(value: string, upgradeHttp = false): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw forbidden(); }
  if (upgradeHttp && url.protocol === 'http:') url.protocol = 'https:';
  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  if (value.length > 2048 || url.protocol !== 'https:' || url.username || url.password || url.hash
    || (url.port && url.port !== '443') || !host.includes('.')
    || isIP(host.replace(/^\[|\]$/g, ''))
    || !host.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
    || /\.(localhost|local|internal|invalid|test|onion)$/.test(host)
    || host.endsWith('.home.arpa')) throw forbidden();
  url.hostname = host;
  return url;
}

export async function limitedImportBody(response: Response, max: number): Promise<Uint8Array> {
  if (Number(response.headers.get('Content-Length')) > max) {
    await response.body?.cancel().catch(() => {});
    throw new ApiError(422, 'ImportPayloadTooLarge', 'The source response exceeds the import size limit.');
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader(), chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > max) throw new ApiError(422, 'ImportPayloadTooLarge', 'The source response exceeds the import size limit.');
      chunks.push(value);
    }
  } finally { await reader.cancel().catch(() => {}); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return bytes;
}

/** Public-only import fetcher for the Worker. No application headers/keys are forwarded. */
export class ImportReader {
  private checkedHosts = new Set<string>();
  private requests = 0;
  private signal = AbortSignal.timeout(15_000);

  private async checkDns(host: string) {
    if (this.checkedHosts.has(host)) return;
    let hasAddress = false;
    for (const type of ['A', 'AAAA']) {
      const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`, {
        headers: { Accept: 'application/dns-json' }, redirect: 'error', signal: this.signal,
      });
      if (!response.ok) throw failure();
      const data = JSON.parse(new TextDecoder().decode(await limitedImportBody(response, 32 * 1024))) as {
        Status?: number; Answer?: { type: number; data: string }[];
      };
      if (data.Status !== 0 || !Array.isArray(data.Answer) && data.Answer !== undefined) throw failure();
      for (const answer of data.Answer ?? []) {
        if (answer.type !== 1 && answer.type !== 28) continue;
        if (!ipaddr.isValid(answer.data) || ipaddr.process(answer.data).range() !== 'unicast') throw forbidden();
        // Record after both families have been inspected, including private AAAA answers.
        hasAddress = true;
      }
    }
    if (!hasAddress) throw failure();
    this.checkedHosts.add(host);
  }
  async response(value: string | URL, options: { method?: 'GET' | 'POST'; body?: string; allowedHost?: (host: string) => boolean } = {}) {
    let url = publicImportUrl(String(value));
    let method = options.method ?? 'GET', body = options.body;
    for (let redirects = 0; redirects <= 3; redirects++) {
      if (++this.requests > 12) throw new ApiError(422, 'ImportTooManyRedirects', 'The source service made too many redirects.');
      if (options.allowedHost && !options.allowedHost(url.hostname)) {
        throw new ApiError(422, 'ImportSkinDomainMismatch', 'The texture host is not declared by the source Authlib service.');
      }
      await this.checkDns(url.hostname);
      const response = await fetch(url.href, {
        method, ...(body === undefined ? {} : { body }), redirect: 'manual', signal: this.signal,
        headers: { Accept: 'application/json, image/png', 'User-Agent': 'CubAuth-Profile-Importer/1.0',
          ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      });
      if (![301, 302, 303, 307, 308].includes(response.status)) return { response, url };
      const location = response.headers.get('Location');
      await response.body?.cancel().catch(() => {});
      if (!location) throw failure();
      url = publicImportUrl(new URL(location, url).href);
      if (response.status === 303 || ([301, 302].includes(response.status) && method === 'POST')) {
        method = 'GET'; body = undefined;
      }
    }
    throw new ApiError(422, 'ImportTooManyRedirects', 'The source service made too many redirects.');
  }

  async json(value: string | URL, options: { method?: 'GET' | 'POST'; body?: string } = {}): Promise<unknown> {
    const { response } = await this.response(value, options);
    if (response.status === 204 || response.status === 404) { await response.body?.cancel().catch(() => {}); return null; }
    if (!response.ok) {
      await response.body?.cancel().catch(() => {});
      throw new ApiError(502, 'ImportProviderRejected', `The source service rejected the profile request (HTTP ${response.status}).`);
    }
    return this.parseJson(response);
  }

  async parseJson(response: Response): Promise<unknown> {
    const bytes = await limitedImportBody(response, 128 * 1024);
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes)); }
    catch { throw new ApiError(422, 'ImportInvalidProfile', 'The source did not return a valid Yggdrasil profile.'); }
  }
}
