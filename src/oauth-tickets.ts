import { Database } from './database';
import { newToken, sha256 } from './crypto';
import type { Env } from './types';

export async function beginLogin(env: Env, challenge: string) {
  const state = newToken();
  await new Database(env)
    .statement(
      'INSERT INTO oauth_states(state_hash, challenge, expires_at) VALUES (?, ?, unixepoch() + 600)',
      await sha256(state),
      challenge,
    )
    .run();
  return state;
}
export async function consumeState(env: Env, state: string) {
  return new Database(env)
    .statement(
      'DELETE FROM oauth_states WHERE state_hash = ? AND expires_at > unixepoch() RETURNING challenge',
      await sha256(state),
    )
    .first<{ challenge: string }>();
}
export async function createLoginTicket(env: Env, discordId: string, challenge: string) {
  const ticket = newToken();
  await new Database(env)
    .statement(
      'INSERT INTO login_tickets(token_hash, discord_id, challenge, expires_at) VALUES (?, ?, ?, unixepoch() + 300)',
      await sha256(ticket),
      discordId,
      challenge,
    )
    .run();
  return ticket;
}
export async function consumeLoginTicket(env: Env, code: string, verifier: string) {
  return new Database(env)
    .statement(
      `DELETE FROM login_tickets WHERE token_hash = ? AND challenge = ?
    AND expires_at > unixepoch() RETURNING discord_id`,
      await sha256(code),
      await sha256(verifier),
    )
    .first<{ discord_id: string }>();
}
