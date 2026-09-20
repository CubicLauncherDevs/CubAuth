import type { Env } from './types';

const encoder = new TextEncoder();
export const bytes = (value: string) => encoder.encode(value);
export const hex = (value: ArrayBuffer) => Array.from(new Uint8Array(value), b => b.toString(16).padStart(2, '0')).join('');
export const sha256 = async (value: Uint8Array | string) => hex(await crypto.subtle.digest('SHA-256', typeof value === 'string' ? bytes(value) : value));
export const newToken = () => hex(crypto.getRandomValues(new Uint8Array(32)).buffer);
export const compactUuid = (id: string) => id.replaceAll('-', '');
export const pem = (value: string) => value.replaceAll('\\n', '\n').trim();

export function base64(value: Uint8Array): string {
  let binary = '';
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}

let cachedPem: string;
let cachedKey: Promise<CryptoKey> | undefined;
export async function signProperty(value: string, env: Env): Promise<string> {
  const privatePem = pem(env.SIGNING_PRIVATE_KEY);
  if (cachedPem !== privatePem || !cachedKey) {
    const der = Uint8Array.from(atob(privatePem.replace(/-----[^-]+-----|\s/g, '')), c => c.charCodeAt(0));
    cachedPem = privatePem;
    cachedKey = crypto.subtle.importKey('pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' }, false, ['sign']);
  }
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', await cachedKey, bytes(value));
  return base64(new Uint8Array(signature));
}
