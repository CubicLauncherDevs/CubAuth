import { isIP } from 'node:net';
import { ApiError, badRequest } from './errors';

export async function readBody(request: Request, max: number): Promise<Uint8Array> {
  if (Number(request.headers.get('Content-Length')) > max) throw new ApiError(413, 'PayloadTooLarge', 'Request body too large.');
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > max) throw new ApiError(413, 'PayloadTooLarge', 'Request body too large.');
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const result = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; }
  return result;
}

export async function jsonBody(request: Request): Promise<Record<string, unknown>> {
  const data = await jsonValue(request);
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw badRequest('Expected a JSON object.');
  return data as Record<string, unknown>;
}

export async function jsonValue(request: Request): Promise<unknown> {
  if (request.headers.get('Content-Type')?.split(';')[0]?.trim() !== 'application/json') throw new ApiError(415, 'UnsupportedMediaType', 'Use application/json.');
  const raw = await readBody(request, 16 * 1024);
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(raw)); }
  catch { throw badRequest('Invalid JSON.'); }
}

export function text(value: unknown, name: string, max = 1024): string {
  if (typeof value !== 'string' || !value.length || value.length > max) throw badRequest(`Invalid ${name}.`);
  return value;
}

export function optionalClient(value: unknown): string | null {
  return value === undefined ? null : text(value, 'clientToken');
}

export function requestUser(value: unknown): boolean {
  if (value !== undefined && typeof value !== 'boolean') throw badRequest('Invalid requestUser.');
  return value === true;
}

export function uuid(value: unknown): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{32}$/i.test(value)) throw badRequest('Expected a UUID without hyphens.');
  return `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`.toLowerCase();
}

export function ip(value: string): string {
  if (!isIP(value)) throw badRequest('Invalid IP address.');
  return value;
}
