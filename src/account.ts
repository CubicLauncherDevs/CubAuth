import { Hono, type Context } from 'hono';
import { rateLimit, WEB_SESSION_TTL } from './auth';
import { accessToken, clearSessionCookie, sessionToken, setSessionCookie } from './cookies';
import { newToken, sha256 } from './crypto';
import { Database } from './database';
import { ApiError, badRequest } from './errors';
import { issueLauncherToken } from './launcher-tokens';
import { sessionResponse } from './profiles';
import type { Env } from './types';
import { jsonBody, optionalClient, text } from './validation';

export const accountRoutes = new Hono<{ Bindings: Env }>();
async function currentAccount(c: Context<{ Bindings: Env }>) {
  const token = sessionToken(c);
  if (!token) throw new ApiError(401, 'Unauthorized', 'Sign in with Discord.');
  const db = new Database(c.env),
    hash = await sha256(token);
  const session = await db.session(hash, null, 'web');
  if (!session) throw new ApiError(401, 'Unauthorized', 'Sign in with Discord.');
  return { db, hash, session };
}

/** Rehydrates the panel from the HttpOnly cookie after a new tab or browser restart. */
accountRoutes.get('/session', async (c) => {
  const { session } = await currentAccount(c);
  return c.json(sessionResponse(session, sessionToken(c)!, false));
});

accountRoutes.get('/me', async (c) => {
  const { db, session } = await currentAccount(c);
  const row = await db
    .statement(
      'SELECT created_at, discord_email FROM accounts WHERE discord_id = ?',
      session.discord_id,
    )
    .first<{ created_at: number; discord_email: string | null }>();
  const history = await db
    .statement(
      'SELECT previous_name, new_name, changed_at FROM name_history WHERE profile_id = ? ORDER BY id DESC LIMIT 20',
      session.profile.id,
    )
    .all<{ previous_name: string; new_name: string; changed_at: number }>();
  const count = await db
    .statement('SELECT count(*) AS total FROM name_history WHERE profile_id = ?', session.profile.id)
    .first<{ total: number }>();
  return c.json({
    discordId: session.discord_id,
    discordEmail: row!.discord_email,
    createdAt: new Date(row!.created_at * 1000).toISOString(),
    nameHistory: history.results.map((item) => ({
      previousName: item.previous_name,
      newName: item.new_name,
      changedAt: new Date(item.changed_at * 1000).toISOString(),
    })),
    historyTotal: count!.total,
  });
});

accountRoutes.post('/launcher-token', async (c) => {
  const { db, hash, session } = await currentAccount(c);
  await rateLimit(db, 'launcher-token', session.discord_id, 10, 600);
  return c.json({
    token: await issueLauncherToken(c.env.DB, session.discord_id, hash),
    username: session.profile.name,
    expiresAt: new Date(Date.now() + 3600000).toISOString(),
  });
});

accountRoutes.post('/username', async (c) => {
  const { db, hash, session } = await currentAccount(c),
    body = await jsonBody(c.req.raw);
  const name = text(body.username, 'username', 16);
  if (!/^[A-Za-z0-9_]{3,16}$/.test(name)) throw badRequest('Use 3–16 letters, numbers or underscores.');
  await rateLimit(db, 'rename', session.discord_id, 5, 3600);
  try {
    const updated = await db
      .statement(
        `UPDATE profiles SET name = ? WHERE id = ? AND EXISTS (
      SELECT 1 FROM sessions s JOIN accounts a ON a.discord_id = s.discord_id WHERE s.token_hash = ?
      AND s.expires_at > unixepoch() AND a.disabled = 0 AND s.kind = 'web')`,
        name,
        session.profile.id,
        hash,
      )
      .run();
    if (!updated.meta.changes) throw new ApiError(401, 'Unauthorized', 'Session expired.');
  } catch (error) {
    if (String(error).includes('UNIQUE constraint failed: profiles.name'))
      throw new ApiError(409, 'UsernameTaken', 'That player name is already taken.');
    throw error;
  }
  const token = newToken();
  const renewed = await db.refresh(hash, await sha256(token), session.client_token, WEB_SESSION_TTL, 'web');
  if (!renewed) throw new ApiError(401, 'Unauthorized', 'Session expired.');
  setSessionCookie(c, token);
  return c.json({ session: sessionResponse(renewed, token, false) });
});

accountRoutes.post('/session/validate', async (c) => {
  const body = await jsonBody(c.req.raw);
  if (
    !(await new Database(c.env).session(
      await sha256(accessToken(c, body)),
      optionalClient(body.clientToken),
      'web',
    ))
  )
    throw new ApiError(401, 'Unauthorized', 'Session expired.');
  return c.body(null, 204);
});
accountRoutes.post('/session/refresh', async (c) => {
  const body = await jsonBody(c.req.raw),
    db = new Database(c.env),
    hash = await sha256(accessToken(c, body));
  const current = await db.session(hash, optionalClient(body.clientToken), 'web');
  if (!current) throw new ApiError(401, 'Unauthorized', 'Session expired.');
  const token = newToken(),
    session = await db.refresh(hash, await sha256(token), current.client_token, WEB_SESSION_TTL, 'web');
  if (!session) throw new ApiError(401, 'Unauthorized', 'Session expired.');
  setSessionCookie(c, token);
  return c.json(sessionResponse(session, token, false));
});
accountRoutes.post('/session/logout', async (c) => {
  const body = await jsonBody(c.req.raw);
  await new Database(c.env)
    .statement(
      "DELETE FROM sessions WHERE token_hash = ? AND kind = 'web'",
      await sha256(accessToken(c, body)),
    )
    .run();
  clearSessionCookie(c);
  return c.body(null, 204);
});
accountRoutes.post('/signout-all', async (c) => {
  const { db, session } = await currentAccount(c);
  await db.db.batch([
    db.statement('DELETE FROM sessions WHERE discord_id = ?', session.discord_id),
    db.statement('DELETE FROM launcher_tokens WHERE discord_id = ?', session.discord_id),
    db.statement('DELETE FROM login_tickets WHERE discord_id = ?', session.discord_id),
    db.statement('DELETE FROM registrations WHERE discord_id = ?', session.discord_id),
  ]);
  clearSessionCookie(c);
  return c.body(null, 204);
});
