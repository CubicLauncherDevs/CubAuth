import { ApiError, badRequest } from './errors';
import type { Env, Profile, Session } from './types';

const profileColumns = 'p.id, a.id AS user_id, p.name, p.skin_hash, p.skin_model';
type SessionRow = Profile & { discord_id: string; client_token: string; kind: Session['kind'] };
const toSession = (row: SessionRow | null): Session | null =>
  row
    ? {
        user_id: row.user_id,
        discord_id: row.discord_id,
        client_token: row.client_token,
        kind: row.kind,
        profile: {
          id: row.id,
          user_id: row.user_id,
          name: row.name,
          skin_hash: row.skin_hash,
          skin_model: row.skin_model,
        },
      }
    : null;

export class Database {
  constructor(public env: Env) {}
  get db() {
    return this.env.DB;
  }
  statement(sql: string, ...values: unknown[]) {
    return this.db.prepare(sql).bind(...values);
  }

  sessionLimit(discordId: string, kind: Session['kind']) {
    return this.statement(
      `DELETE FROM sessions WHERE discord_id = ? AND kind = ? AND (
      expires_at <= unixepoch() OR token_hash IN (SELECT token_hash FROM sessions
      WHERE discord_id = ? AND kind = ? ORDER BY rowid DESC LIMIT -1 OFFSET 10))`,
      discordId,
      kind,
      discordId,
      kind,
    );
  }

  async profileForDiscord(discordId: string): Promise<Profile | null> {
    const account = await this.statement(
      'SELECT disabled FROM accounts WHERE discord_id = ?',
      discordId,
    ).first<{ disabled: number }>();
    if (account?.disabled) throw new ApiError(403, 'AccountBanned', 'This account is disabled.');
    return this.statement(
      `SELECT ${profileColumns} FROM profiles p JOIN accounts a ON a.discord_id = p.discord_id WHERE p.discord_id = ? AND a.disabled = 0`,
      discordId,
    ).first<Profile>();
  }

  async register(discordId: string, name: string, discordEmail: string | null = null): Promise<Profile> {
    if (!/^[A-Za-z0-9_]{3,16}$/.test(name)) throw badRequest('Use 3–16 letters, numbers or underscores.');
    const existing = await this.profileForDiscord(discordId);
    if (existing) return existing;
    if (this.env.ALLOW_REGISTRATION !== 'true')
      throw new ApiError(403, 'RegistrationDisabled', 'Registration is disabled.');
    try {
      await this.db.batch([
        this.statement(
          'INSERT INTO accounts(discord_id, id, discord_email) VALUES (?, ?, ?) ON CONFLICT(discord_id) DO NOTHING',
          discordId,
          crypto.randomUUID(),
          discordEmail,
        ),
        this.statement(
          `INSERT INTO profiles(id, discord_id, name) SELECT ?, discord_id, ? FROM accounts
          WHERE discord_id = ? AND disabled = 0 ON CONFLICT(discord_id) DO NOTHING`,
          crypto.randomUUID(),
          name,
          discordId,
        ),
      ]);
    } catch (error) {
      if (String(error).includes('UNIQUE constraint failed: profiles.name'))
        throw new ApiError(409, 'UsernameTaken', 'That player name is already taken.');
      throw error;
    }
    const profile = await this.profileForDiscord(discordId);
    if (!profile) throw new ApiError(403, 'AccountBanned', 'This account is disabled.');
    return profile;
  }

  async session(
    hash: string,
    client: string | null = null,
    kind: Session['kind'] | null = null,
  ): Promise<Session | null> {
    return toSession(
      await this.statement(
        `SELECT ${profileColumns}, s.discord_id, s.client_token, s.kind
      FROM sessions s JOIN profiles p ON p.id = s.profile_id JOIN accounts a ON a.discord_id = s.discord_id
      WHERE s.token_hash = ? AND s.expires_at > unixepoch() AND a.disabled = 0
      AND (? IS NULL OR s.client_token = ?) AND (? IS NULL OR s.kind = ?)`,
        hash,
        client,
        client,
        kind,
        kind,
      ).first<SessionRow>(),
    );
  }

  async issueSession(
    discordId: string,
    hash: string,
    client: string,
    ttl: number,
    kind: Session['kind'],
  ): Promise<Session | null> {
    await this.db.batch([
      this.statement(
        `INSERT INTO sessions(token_hash, discord_id, profile_id, client_token, expires_at, kind)
      SELECT ?, p.discord_id, p.id, ?, unixepoch() + ?, ? FROM profiles p JOIN accounts a ON a.discord_id = p.discord_id
      WHERE p.discord_id = ? AND a.disabled = 0`,
        hash,
        client,
        ttl,
        kind,
        discordId,
      ),
      this.sessionLimit(discordId, kind),
    ]);
    return this.session(hash, client, kind);
  }

  async refresh(
    hash: string,
    nextHash: string,
    client: string | null,
    ttl: number,
    kind: Session['kind'],
  ): Promise<Session | null> {
    await this.db.batch([
      this.statement(
        `INSERT INTO sessions(token_hash, discord_id, profile_id, client_token, expires_at, kind)
        SELECT ?, s.discord_id, s.profile_id, s.client_token, unixepoch() + ?, s.kind FROM sessions s
        JOIN accounts a ON a.discord_id = s.discord_id WHERE s.token_hash = ? AND s.kind = ?
        AND s.expires_at > unixepoch() AND a.disabled = 0 AND (? IS NULL OR s.client_token = ?)`,
        nextHash,
        ttl,
        hash,
        kind,
        client,
        client,
      ),
      this.statement(
        'DELETE FROM sessions WHERE token_hash = ? AND EXISTS (SELECT 1 FROM sessions WHERE token_hash = ?)',
        hash,
        nextHash,
      ),
    ]);
    return this.session(nextHash, client, kind);
  }

  // Named operations preserve the Yggdrasil routes while executing directly in D1.
  async rpc<T>(name: string, args: Record<string, unknown> = {}): Promise<T> {
    const v = (key: string) => args[key] ?? null;
    let result: unknown;
    switch (name) {
      case 'cubauth_rate_limit': {
        const row = await this.statement(
          `INSERT INTO rate_limits(key, hits, expires_at) VALUES (?, 1, unixepoch() + ?)
          ON CONFLICT(key) DO UPDATE SET hits = CASE WHEN rate_limits.expires_at <= unixepoch() THEN 1 ELSE min(rate_limits.hits + 1, ? + 1) END,
          expires_at = CASE WHEN rate_limits.expires_at <= unixepoch() THEN excluded.expires_at ELSE rate_limits.expires_at END RETURNING hits`,
          v('p_key'),
          v('p_window'),
          v('p_limit'),
        ).first<{ hits: number }>();
        result = !!row && row.hits <= Number(v('p_limit'));
        break;
      }
      case 'cubauth_session':
        result = await this.session(String(v('p_hash')), v('p_client') as string | null, 'launcher');
        break;
      case 'cubauth_refresh':
        result = await this.refresh(
          String(v('p_hash')),
          String(v('p_new_hash')),
          v('p_client') as string | null,
          Number(v('p_ttl')),
          'launcher',
        );
        break;
      case 'cubauth_invalidate':
        await this.statement(
          "DELETE FROM sessions WHERE token_hash = ? AND kind = 'launcher'",
          v('p_hash'),
        ).run();
        result = null;
        break;
      case 'cubauth_join': {
        const changed = await this.statement(
          `INSERT INTO joins(server_id, profile_id, token_hash, ip, expires_at)
          SELECT ?, s.profile_id, s.token_hash, ?, unixepoch() + 30 FROM sessions s JOIN accounts a ON a.discord_id = s.discord_id
          WHERE s.token_hash = ? AND s.profile_id = ? AND s.kind = 'launcher' AND s.expires_at > unixepoch() AND a.disabled = 0
          ON CONFLICT(server_id, profile_id) DO UPDATE SET token_hash = excluded.token_hash, ip = excluded.ip, expires_at = excluded.expires_at`,
          v('p_server'),
          v('p_ip'),
          v('p_hash'),
          v('p_profile'),
        ).run();
        result = changed.meta.changes > 0;
        break;
      }
      case 'cubauth_has_joined':
        result = await this.statement(
          `SELECT ${profileColumns} FROM joins j JOIN sessions s ON s.token_hash = j.token_hash
        JOIN profiles p ON p.id = j.profile_id JOIN accounts a ON a.discord_id = p.discord_id
        WHERE j.server_id = ? AND p.name = ? COLLATE NOCASE AND j.expires_at > unixepoch() AND s.expires_at > unixepoch()
        AND a.disabled = 0 AND (? IS NULL OR j.ip = ?) LIMIT 1`,
          v('p_server'),
          v('p_name'),
          v('p_ip'),
          v('p_ip'),
        ).first<Profile>();
        break;
      case 'cubauth_profile':
        result = await this.statement(
          `SELECT ${profileColumns} FROM profiles p JOIN accounts a ON a.discord_id = p.discord_id WHERE p.id = ? AND a.disabled = 0`,
          v('p_id'),
        ).first<Profile>();
        break;
      case 'cubauth_profiles': {
        const names = args.p_names as string[];
        result = names.length
          ? (
              await this.statement(
                `SELECT replace(p.id, '-', '') AS id, p.name FROM profiles p JOIN accounts a ON a.discord_id = p.discord_id WHERE a.disabled = 0 AND p.name IN (${names.map(() => '?').join(',')})`,
                ...names,
              ).all()
            ).results
          : [];
        break;
      }
      case 'cubauth_set_skin': {
        const changed = await this.statement(
          `UPDATE profiles SET skin_hash = ?, skin_model = ? WHERE id = ? AND EXISTS (
          SELECT 1 FROM sessions s JOIN accounts a ON a.discord_id = s.discord_id WHERE s.token_hash = ?
          AND s.profile_id = profiles.id AND s.expires_at > unixepoch() AND a.disabled = 0)`,
          v('p_skin'),
          v('p_model'),
          v('p_profile'),
          v('p_hash'),
        ).run();
        result = changed.meta.changes > 0;
        break;
      }
      case 'cubauth_cleanup':
        await this.db.batch(
          [
            'joins',
            'sessions',
            'rate_limits',
            'launcher_tokens',
            'oauth_states',
            'login_tickets',
            'registrations',
            'legacy_tickets',
          ].map((table) => this.db.prepare(`DELETE FROM ${table} WHERE expires_at <= unixepoch()`)),
        );
        result = null;
        break;
      default:
        throw new Error(`Unsupported database operation: ${name}`);
    }
    return result as T;
  }
}
