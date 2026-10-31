import type { Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { WEB_SESSION_TTL } from './auth';
import { text } from './validation';

export const SESSION_COOKIE = 'cubauth_session';
const TOKEN = /^[a-f0-9]{64}$/i;
const secure = (c: Context) => new URL(c.req.url).protocol === 'https:';

export function bearerToken(c: Context): string | null {
  return c.req.header('Authorization')?.match(/^Bearer ([a-f0-9]{64})$/i)?.[1] ?? null;
}

export function cookieToken(c: Context): string | null {
  const value = getCookie(c, SESSION_COOKIE);
  return value && TOKEN.test(value) ? value : null;
}

/** An explicit bearer token wins over the browser cookie. */
export function sessionToken(c: Context): string | null {
  return bearerToken(c) ?? cookieToken(c);
}

/** Body token first, then Authorization, then the HttpOnly session cookie. */
export function accessToken(c: Context, body: Record<string, unknown>): string {
  return body.accessToken === undefined
    ? (sessionToken(c) ?? text(body.accessToken, 'accessToken'))
    : text(body.accessToken, 'accessToken');
}

export function setSessionCookie(c: Context, token: string) {
  setCookie(c, SESSION_COOKIE, token, {
    httpOnly: true,
    secure: secure(c),
    sameSite: 'Lax',
    path: '/',
    maxAge: WEB_SESSION_TTL,
  });
}

export function clearSessionCookie(c: Context) {
  deleteCookie(c, SESSION_COOKIE, { path: '/', secure: secure(c), sameSite: 'Lax' });
}
