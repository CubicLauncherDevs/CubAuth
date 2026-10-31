import { newToken, sha256 } from './crypto';
import { Database } from './database';
import { ApiError, invalidCredentials } from './errors';
import { tokenTtl } from './auth';
import type { Env } from './types';

/** Only the hash is stored; generating another token revokes the previous one. */
export async function issueLauncherToken(
  db: D1Database,
  discordId: string,
  webHash: string,
): Promise<string> {
  const token = newToken();
  const results = await db.batch([
    db.prepare('DELETE FROM launcher_tokens WHERE discord_id = ?').bind(discordId),
    db
      .prepare(
        `INSERT INTO launcher_tokens(token_hash, discord_id, expires_at)
      SELECT ?, a.discord_id, unixepoch() + 3600 FROM accounts a WHERE a.discord_id = ? AND a.disabled = 0
      AND EXISTS (SELECT 1 FROM sessions s WHERE s.token_hash = ? AND s.discord_id = a.discord_id
        AND s.kind = 'web' AND s.expires_at > unixepoch())`,
      )
      .bind(await sha256(token), discordId, webHash),
  ]);
  if (!results[1]?.meta.changes) throw new ApiError(401, 'Unauthorized', 'Sign in with Discord again.');
  return token;
}

/** Token consumption and session creation commit together, including concurrent logins. */
export async function authenticateLauncher(env: Env, username: string, token: string, client: string) {
  if (!/^[a-f0-9]{64}$/.test(token)) throw invalidCredentials();
  const database = new Database(env),
    hash = await sha256(token);
  const identity = await database
    .statement(
      `SELECT t.discord_id FROM launcher_tokens t JOIN profiles p ON p.discord_id = t.discord_id
    JOIN accounts a ON a.discord_id = t.discord_id WHERE t.token_hash = ? AND t.expires_at > unixepoch()
    AND p.name = ? COLLATE NOCASE AND a.disabled = 0`,
      hash,
      username,
    )
    .first<{ discord_id: string }>();
  if (!identity) throw invalidCredentials();
  const accessToken = newToken(),
    sessionHash = await sha256(accessToken);
  await env.DB.batch([
    database.statement(
      `INSERT INTO sessions(token_hash, discord_id, profile_id, client_token, expires_at, kind)
      SELECT ?, t.discord_id, p.id, ?, unixepoch() + ?, 'launcher' FROM launcher_tokens t
      JOIN profiles p ON p.discord_id = t.discord_id JOIN accounts a ON a.discord_id = t.discord_id
      WHERE t.token_hash = ? AND t.expires_at > unixepoch() AND p.name = ? COLLATE NOCASE AND a.disabled = 0`,
      sessionHash,
      client,
      tokenTtl(env),
      hash,
      username,
    ),
    database.statement(
      'DELETE FROM launcher_tokens WHERE token_hash = ? AND EXISTS (SELECT 1 FROM sessions WHERE token_hash = ?)',
      hash,
      sessionHash,
    ),
    database.sessionLimit(identity.discord_id, 'launcher'),
  ]);
  const session = await database.session(sessionHash, client, 'launcher');
  if (!session) throw invalidCredentials();
  return { session, accessToken };
}
