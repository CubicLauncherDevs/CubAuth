import { ApiError } from './errors';

/** Discord configuration remains server-side; secrets are never sent to browsers. */
export interface DiscordConfig {
  DISCORD_CLIENT_ID: string;
  DISCORD_CLIENT_SECRET: string;
  PUBLIC_URL: string;
}

const API = 'https://discord.com/api/v10';
const callback = (env: DiscordConfig) => `${env.PUBLIC_URL.replace(/\/$/, '')}/discord/callback`;

export function discordAuthorizationUrl(env: DiscordConfig, state: string): string {
  if (!/^\d{1,20}$/.test(env.DISCORD_CLIENT_ID) || !env.DISCORD_CLIENT_SECRET) {
    throw new ApiError(503, 'ConfigurationError', 'Configure Discord credentials first.');
  }
  const url = new URL('https://discord.com/oauth2/authorize');
  url.search = new URLSearchParams({
    client_id: env.DISCORD_CLIENT_ID,
    response_type: 'code',
    redirect_uri: callback(env),
    scope: 'identify email',
    state,
  }).toString();
  return url.toString();
}

export interface DiscordUser {
  id: string;
  email: string | null;
}

export async function discordIdentity(env: DiscordConfig, code: string): Promise<DiscordUser> {
  const tokenResponse = await fetch(`${API}/oauth2/token`, {
    signal: AbortSignal.timeout(10_000),
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: env.DISCORD_CLIENT_ID,
      client_secret: env.DISCORD_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: callback(env),
    }),
  });
  if (!tokenResponse.ok) throw new ApiError(403, 'DiscordLoginFailed', 'Discord authorization failed.');
  const token = (await tokenResponse.json()) as { access_token?: unknown };
  if (typeof token.access_token !== 'string')
    throw new ApiError(503, 'DiscordUnavailable', 'Discord authorization unavailable.');
  const response = await fetch(`${API}/users/@me`, {
    signal: AbortSignal.timeout(10_000),
    headers: { Authorization: `Bearer ${token.access_token}` },
  });
  if (!response.ok) throw new ApiError(503, 'DiscordUnavailable', 'Discord identity unavailable.');
  const user = (await response.json()) as { id?: unknown; email?: unknown };
  if (typeof user.id !== 'string' || !/^\d{1,20}$/.test(user.id))
    throw new ApiError(503, 'DiscordUnavailable', 'Invalid Discord identity.');
  return {
    id: user.id,
    email:
      typeof user.email === 'string' && user.email.length > 0 && user.email.length <= 254
        ? user.email
        : null,
  };
}
