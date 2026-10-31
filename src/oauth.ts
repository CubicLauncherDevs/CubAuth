import { Hono, type Context } from 'hono';
import { rateLimit, WEB_SESSION_TTL } from './auth';
import { setSessionCookie } from './cookies';
import { newToken, sha256 } from './crypto';
import { Database } from './database';
import { discordAuthorizationUrl, discordIdentity } from './discord';
import { ApiError, badRequest } from './errors';
import { linkLegacy } from './migration';
import { sessionResponse } from './profiles';
import type { Env } from './types';
import { jsonBody, text } from './validation';
import { beginLogin, consumeState, createLoginTicket, consumeLoginTicket } from './oauth-tickets';

export const oauthRoutes = new Hono<{ Bindings: Env }>();
const secret = (value: unknown, name: string) => {
  const result = text(value, name, 64);
  if (!/^[a-f0-9]{64}$/.test(result)) throw badRequest(`Invalid ${name}.`);
  return result;
};
export async function webSession(env: Env, discordId: string) {
  const accessToken = newToken();
  const session = await new Database(env).issueSession(
    discordId,
    await sha256(accessToken),
    crypto.randomUUID(),
    WEB_SESSION_TTL,
    'web',
  );
  if (!session) throw new ApiError(403, 'AccountBanned', 'Account unavailable.');
  return sessionResponse(session, accessToken, false);
}

/** The web panel keeps its session in an HttpOnly cookie; the JSON copy stays for clients that store it. */
function sessionJson(c: Context<{ Bindings: Env }>, session: ReturnType<typeof sessionResponse>) {
  setSessionCookie(c, session.accessToken);
  return c.json({ session });
}

oauthRoutes.post('/start', async (c) => {
  const body = await jsonBody(c.req.raw),
    challenge = secret(body.challenge, 'challenge');
  const db = new Database(c.env);
  await rateLimit(db, 'oauth-start', c.req.header('CF-Connecting-IP') ?? '127.0.0.1', 20, 600);
  discordAuthorizationUrl(c.env, 'validate-configuration');
  if (!c.env.ACCOUNT_URL) throw new ApiError(503, 'ConfigurationError', 'Configure ACCOUNT_URL.');
  const state = await beginLogin(c.env, challenge);
  return c.json({ url: discordAuthorizationUrl(c.env, state) });
});

oauthRoutes.get('/callback', async (c) => {
  const destination = `${c.env.ACCOUNT_URL?.replace(/\/$/, '')}/login`;
  try {
    const state = secret(c.req.query('state'), 'state'),
      db = new Database(c.env);
    const pending = await consumeState(c.env, state);
    if (!pending) throw new ApiError(403, 'DiscordStateExpired', 'Start Discord login again.');
    if (c.req.query('error'))
      throw new ApiError(403, 'DiscordLoginCancelled', 'Discord login was cancelled.');
    const user = await discordIdentity(c.env, text(c.req.query('code'), 'code', 2048));
    await db.profileForDiscord(user.id); // Enforce disabled accounts before creating a ticket.
    const ticket = await createLoginTicket(c.env, user.id, pending.challenge, user.email);
    return c.redirect(`${destination}#code=${ticket}`, 302);
  } catch (error) {
    const code = error instanceof ApiError ? error.code : 'DiscordUnavailable';
    return c.redirect(`${destination}#error=${encodeURIComponent(code)}`, 302);
  }
});

oauthRoutes.post('/exchange', async (c) => {
  const body = await jsonBody(c.req.raw),
    db = new Database(c.env);
  await rateLimit(db, 'oauth-exchange', c.req.header('CF-Connecting-IP') ?? '127.0.0.1', 30, 600);
  // A ticket is bound to the secret kept in the initiating tab; copied callback URLs cannot log another browser in.
  const ticket = await consumeLoginTicket(
    c.env,
    secret(body.code, 'code'),
    secret(body.verifier, 'verifier'),
  );
  if (!ticket) throw new ApiError(403, 'DiscordStateExpired', 'Start Discord login again.');
  if (body.migrationToken !== undefined) {
    await linkLegacy(
      db,
      secret(body.migrationToken, 'migrationToken'),
      ticket.discord_id,
      ticket.discord_email,
    );
    return sessionJson(c, await webSession(c.env, ticket.discord_id));
  }
  const profile = await db.profileForDiscord(ticket.discord_id);
  if (profile) {
    if (ticket.discord_email)
      await db
        .statement(
          'UPDATE accounts SET discord_email = ? WHERE discord_id = ?',
          ticket.discord_email,
          ticket.discord_id,
        )
        .run();
    return sessionJson(c, await webSession(c.env, ticket.discord_id));
  }
  if (c.env.ALLOW_REGISTRATION !== 'true')
    throw new ApiError(403, 'RegistrationDisabled', 'Registration is disabled.');
  const registrationToken = newToken();
  await db
    .statement(
      'INSERT INTO registrations(token_hash, discord_id, discord_email, expires_at) VALUES (?, ?, ?, unixepoch() + 600)',
      await sha256(registrationToken),
      ticket.discord_id,
      ticket.discord_email,
    )
    .run();
  return c.json({ registrationToken });
});

oauthRoutes.post('/register', async (c) => {
  const body = await jsonBody(c.req.raw),
    db = new Database(c.env);
  const hash = await sha256(secret(body.registrationToken, 'registrationToken'));
  const registration = await db
    .statement(
      'SELECT discord_id, discord_email FROM registrations WHERE token_hash = ? AND expires_at > unixepoch()',
      hash,
    )
    .first<{ discord_id: string; discord_email: string | null }>();
  if (!registration) throw new ApiError(403, 'DiscordStateExpired', 'Start Discord login again.');
  await rateLimit(db, 'register-discord', registration.discord_id, 10, 600);
  await db.register(
    registration.discord_id,
    text(body.username, 'username', 16),
    registration.discord_email,
  );
  const consumed = await db
    .statement(
      'DELETE FROM registrations WHERE token_hash = ? AND expires_at > unixepoch() RETURNING discord_id',
      hash,
    )
    .first();
  if (!consumed) throw new ApiError(403, 'DiscordStateExpired', 'Start Discord login again.');
  return sessionJson(c, await webSession(c.env, registration.discord_id));
});
