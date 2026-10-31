import { afterEach, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { sqliteD1 } from './d1-harness';
import { Database } from '../src/database';
import { authenticateLauncher, issueLauncherToken } from '../src/launcher-tokens';
import { newToken, sha256 } from '../src/crypto';
import { discordAuthorizationUrl, discordIdentity } from '../src/discord';
import { rateLimit } from '../src/auth';
import { beginLogin, consumeState, createLoginTicket, consumeLoginTicket } from '../src/oauth-tickets';
import { linkLegacy } from '../src/migration';
import type { Env } from '../src/types';

let harness: ReturnType<typeof sqliteD1>, env: Env, database: Database, webHash: string;
const originalFetch = globalThis.fetch;
beforeEach(async () => {
  harness = sqliteD1();
  env = {
    DB: harness.db,
    PUBLIC_URL: 'https://auth.example.com',
    ACCOUNT_URL: 'https://accounts.example.com',
    DISCORD_CLIENT_ID: '111',
    DISCORD_CLIENT_SECRET: 'secret',
    ALLOW_REGISTRATION: 'true',
    TOKEN_TTL_SECONDS: '3600',
  } as Env;
  database = new Database(env);
  await database.register('333', 'PlayerOne');
  webHash = await sha256(newToken());
  await database.issueSession('333', webHash, 'web-client', 28800, 'web');
  globalThis.fetch = async () => Response.json({ user: { id: '333' } });
});
afterEach(() => {
  globalThis.fetch = originalFetch;
  harness.close();
});

test('registration is unique per Discord and player name, with rollback on collisions', async () => {
  const first = await database.profileForDiscord('333');
  assert.equal((await database.register('333', 'OtherName')).id, first!.id);
  await assert.rejects(database.register('444', 'playerone'), { code: 'UsernameTaken' });
  assert.equal(harness.sqlite.prepare("SELECT * FROM accounts WHERE discord_id = '444'").get(), undefined);
  await assert.rejects(database.register('444', 'invalid name'));
  const concurrent = await Promise.all([
    database.register('555', 'PlayerTwo'),
    database.register('555', 'PlayerThree'),
  ]);
  assert.equal(concurrent[0]!.id, concurrent[1]!.id);
});
test('closed registration allows existing accounts, and disabled accounts cannot regain access', async () => {
  env.ALLOW_REGISTRATION = 'false';
  assert.equal((await database.register('333', 'Existing')).name, 'PlayerOne');
  await assert.rejects(database.register('444', 'NewPlayer'), { code: 'RegistrationDisabled' });
  harness.sqlite.exec("UPDATE accounts SET disabled = 1 WHERE discord_id = '333'");
  await assert.rejects(database.profileForDiscord('333'), { code: 'AccountBanned' });
  assert.equal(await database.session(webHash), null);
  assert.equal(await database.issueSession('333', 'new-hash', 'client', 60, 'web'), null);
});
test('launcher token stores only its hash, expires in one hour, and consumes once under a race', async () => {
  const token = await issueLauncherToken(env.DB, '333', webHash);
  const row = harness.sqlite
    .prepare('SELECT token_hash, expires_at - unixepoch() AS ttl FROM launcher_tokens')
    .get()!;
  assert.equal(row.token_hash, await sha256(token));
  assert.equal(row.ttl, 3600);
  const results = await Promise.allSettled([
    authenticateLauncher(env, 'playerone', token, 'first'),
    authenticateLauncher(env, 'PLAYERONE', token, 'second'),
  ]);
  assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
  const succeeded = results.find((result) => result.status === 'fulfilled');
  assert.ok(succeeded?.status === 'fulfilled');
  assert.equal(succeeded.value.session.kind, 'launcher');
  assert.ok(await database.session(await sha256(succeeded.value.accessToken), null, 'launcher'));
  await assert.rejects(authenticateLauncher(env, 'PlayerOne', token, 'third'));
});
test('wrong player, expired tokens, and superseded tokens cannot authenticate', async () => {
  const old = await issueLauncherToken(env.DB, '333', webHash);
  await assert.rejects(authenticateLauncher(env, 'WrongPlayer', old, 'client'));
  const fresh = await issueLauncherToken(env.DB, '333', webHash);
  await assert.rejects(authenticateLauncher(env, 'PlayerOne', old, 'client'));
  harness.sqlite.exec('UPDATE launcher_tokens SET expires_at = unixepoch()');
  await assert.rejects(authenticateLauncher(env, 'PlayerOne', fresh, 'client'));
  assert.equal(
    harness.sqlite.prepare("SELECT count(*) AS n FROM sessions WHERE kind = 'launcher'").get()!.n,
    0,
  );
});
test('revoked and launcher sessions cannot mint new launcher credentials', async () => {
  const token = await issueLauncherToken(env.DB, '333', webHash);
  const login = await authenticateLauncher(env, 'PlayerOne', token, 'client');
  await assert.rejects(issueLauncherToken(env.DB, '333', await sha256(login.accessToken)), {
    code: 'Unauthorized',
  });
  harness.sqlite.exec("DELETE FROM sessions WHERE kind = 'web'");
  await assert.rejects(issueLauncherToken(env.DB, '333', webHash), { code: 'Unauthorized' });
});
test('failed session insertion rolls back and preserves the one-use token', async () => {
  const token = await issueLauncherToken(env.DB, '333', webHash);
  harness.sqlite.exec(
    "CREATE TRIGGER fail_session BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT, 'simulate failure'); END",
  );
  await assert.rejects(authenticateLauncher(env, 'PlayerOne', token, 'client'));
  assert.equal(harness.sqlite.prepare('SELECT count(*) AS n FROM launcher_tokens').get()!.n, 1);
});
test('failure consuming a token rolls back the session insertion too', async () => {
  const token = await issueLauncherToken(env.DB, '333', webHash);
  harness.sqlite.exec(
    "CREATE TRIGGER fail_consumption BEFORE DELETE ON launcher_tokens BEGIN SELECT RAISE(ABORT, 'simulate failure'); END",
  );
  await assert.rejects(authenticateLauncher(env, 'PlayerOne', token, 'client'));
  assert.equal(
    harness.sqlite.prepare("SELECT count(*) AS n FROM sessions WHERE kind = 'launcher'").get()!.n,
    0,
  );
  assert.equal(harness.sqlite.prepare('SELECT count(*) AS n FROM launcher_tokens').get()!.n, 1);
});

test('session refresh rotates once, checks client and purpose, and never resurrects expiry', async () => {
  const token = await issueLauncherToken(env.DB, '333', webHash);
  const login = await authenticateLauncher(env, 'PlayerOne', token, 'client'),
    hash = await sha256(login.accessToken);
  assert.equal(await database.session(webHash, null, 'launcher'), null);
  assert.equal(await database.session(hash, null, 'web'), null);
  assert.equal(await database.refresh(hash, 'bad', 'wrong-client', 3600, 'launcher'), null);
  const results = await Promise.all([
    database.refresh(hash, 'next1', 'client', 3600, 'launcher'),
    database.refresh(hash, 'next2', 'client', 3600, 'launcher'),
  ]);
  assert.equal(results.filter(Boolean).length, 1);
  assert.equal(await database.session(hash), null);
  harness.sqlite.exec("UPDATE sessions SET expires_at = unixepoch() WHERE kind = 'launcher'");
  assert.equal(await database.refresh('next1', 'expired', 'client', 3600, 'launcher'), null);
});
test('join validates ownership, server, IP, expiry and revocation', async () => {
  const login = await authenticateLauncher(
    env,
    'PlayerOne',
    await issueLauncherToken(env.DB, '333', webHash),
    'client',
  );
  const hash = await sha256(login.accessToken),
    profileId = login.session.profile.id;
  assert.equal(
    await database.rpc('cubauth_join', {
      p_hash: hash,
      p_profile: 'other',
      p_server: 'server',
      p_ip: '127.0.0.1',
    }),
    false,
  );
  assert.equal(
    await database.rpc('cubauth_join', {
      p_hash: webHash,
      p_profile: profileId,
      p_server: 'server',
      p_ip: '127.0.0.1',
    }),
    false,
  );
  assert.equal(
    await database.rpc('cubauth_join', {
      p_hash: hash,
      p_profile: profileId,
      p_server: 'server',
      p_ip: '127.0.0.1',
    }),
    true,
  );
  assert.ok(
    await database.rpc('cubauth_has_joined', { p_name: 'playerone', p_server: 'server', p_ip: '127.0.0.1' }),
  );
  assert.equal(await database.rpc('cubauth_has_joined', { p_name: 'PlayerOne', p_server: 'other' }), null);
  assert.equal(
    await database.rpc('cubauth_has_joined', { p_name: 'PlayerOne', p_server: 'server', p_ip: '127.0.0.2' }),
    null,
  );
  await database.rpc('cubauth_invalidate', { p_hash: hash });
  assert.equal(await database.rpc('cubauth_has_joined', { p_name: 'PlayerOne', p_server: 'server' }), null);
});
test('skin writes require a live session owning the exact profile', async () => {
  const profile = (await database.profileForDiscord('333'))!;
  assert.equal(
    await database.rpc('cubauth_set_skin', {
      p_hash: webHash,
      p_profile: profile.id,
      p_skin: 'skin',
      p_model: 'slim',
    }),
    true,
  );
  assert.equal(
    await database.rpc('cubauth_set_skin', {
      p_hash: webHash,
      p_profile: 'other',
      p_skin: 'skin',
      p_model: 'slim',
    }),
    false,
  );
  harness.sqlite.exec('UPDATE sessions SET expires_at = unixepoch()');
  assert.equal(
    await database.rpc('cubauth_set_skin', {
      p_hash: webHash,
      p_profile: profile.id,
      p_skin: null,
      p_model: 'default',
    }),
    false,
  );
});
test('name changes preserve UUID, record history, and resolve case-insensitive profile batches', async () => {
  const profile = (await database.profileForDiscord('333'))!;
  await database.statement('UPDATE profiles SET name = ? WHERE id = ?', 'NewName', profile.id).run();
  assert.equal((await database.profileForDiscord('333'))!.id, profile.id);
  assert.equal(
    harness.sqlite.prepare('SELECT previous_name FROM name_history').get()!.previous_name,
    'PlayerOne',
  );
  assert.deepEqual(await database.rpc('cubauth_profiles', { p_names: ['newname'] }), [
    { id: profile.id.replaceAll('-', ''), name: 'NewName' },
  ]);
});
test('rate limits count atomically and cleanup preserves unexpired records', async () => {
  await rateLimit(database, 'test', 'who', 1, 600);
  await assert.rejects(rateLimit(database, 'test', 'who', 1, 600), { code: 'TooManyRequests' });
  harness.sqlite.exec("INSERT INTO oauth_states VALUES ('expired', 'challenge', unixepoch()-1)");
  await database.rpc('cubauth_cleanup');
  assert.equal(harness.sqlite.prepare('SELECT count(*) AS n FROM oauth_states').get()!.n, 0);
  assert.equal(harness.sqlite.prepare('SELECT count(*) AS n FROM sessions').get()!.n, 1);
});

test('caps each kind of session independently without keeping expired sessions', async () => {
  for (let i = 0; i < 12; i++) await database.issueSession('333', 'web-' + i, 'client', 3600, 'web');
  assert.equal(await database.session(webHash), null);
  assert.equal(await database.session('web-0'), null);
  assert.ok(await database.session('web-11'));
  assert.equal(harness.sqlite.prepare("SELECT count(*) AS n FROM sessions WHERE kind = 'web'").get()!.n, 10);
  await database.issueSession('333', 'launcher', 'client', 3600, 'launcher');
  assert.equal(harness.sqlite.prepare('SELECT count(*) AS n FROM sessions').get()!.n, 11);
});

test('records case-only name changes without changing the player identity', async () => {
  const profile = (await database.profileForDiscord('333'))!;
  await database.statement('UPDATE profiles SET name = ? WHERE id = ?', 'playerone', profile.id).run();
  assert.equal(harness.sqlite.prepare('SELECT new_name FROM name_history').get()!.new_name, 'playerone');
  assert.equal((await database.profileForDiscord('333'))!.id, profile.id);
});
test('Discord flow asks for identify and email and exchanges the code server-side', async () => {
  const url = new URL(discordAuthorizationUrl(env, 'state'));
  assert.equal(url.searchParams.get('scope'), 'identify email');
  assert.equal(url.searchParams.get('state'), 'state');
  assert.equal(url.searchParams.get('redirect_uri'), 'https://auth.example.com/discord/callback');
  const paths: string[] = [];
  globalThis.fetch = async (input, init) => {
    const path = new URL(String(input)).pathname;
    paths.push(path);
    if (path.endsWith('/oauth2/token')) {
      assert.equal(new URLSearchParams(String(init!.body)).get('client_secret'), 'secret');
      return Response.json({ access_token: 'discord-token' });
    }
    return Response.json({ id: '333' });
  };
  assert.deepEqual(await discordIdentity(env, 'code'), { id: '333', email: null });
  assert.deepEqual(paths, ['/api/v10/oauth2/token', '/api/v10/users/@me']);
});

test('OAuth state is hashed, expires and can only be consumed once under a race', async () => {
  const verifier = newToken(),
    challenge = await sha256(verifier);
  const state = await beginLogin(env, challenge);
  assert.equal(
    harness.sqlite.prepare('SELECT state_hash FROM oauth_states').get()!.state_hash,
    await sha256(state),
  );
  assert.equal(await consumeState(env, newToken()), null);
  const attempts = await Promise.all([consumeState(env, state), consumeState(env, state)]);
  assert.equal(attempts.filter(Boolean).length, 1);
  assert.equal(attempts.find(Boolean)!.challenge, challenge);
  const expired = await beginLogin(env, challenge);
  harness.sqlite.exec('UPDATE oauth_states SET expires_at = unixepoch()');
  assert.equal(await consumeState(env, expired), null);
});

test('OAuth callback ticket requires the initiating browser secret and cannot be replayed', async () => {
  const verifier = newToken();
  const ticket = await createLoginTicket(env, '333', await sha256(verifier), null);
  assert.equal(await consumeLoginTicket(env, ticket, newToken()), null);
  const attempts = await Promise.all([
    consumeLoginTicket(env, ticket, verifier),
    consumeLoginTicket(env, ticket, verifier),
  ]);
  assert.equal(attempts.filter(Boolean).length, 1);
  assert.equal(attempts.find(Boolean)!.discord_id, '333');
  const expired = await createLoginTicket(env, '333', await sha256(verifier), null);
  harness.sqlite.exec('UPDATE login_tickets SET expires_at = unixepoch()');
  assert.equal(await consumeLoginTicket(env, expired, verifier), null);
});

test('links a verified legacy account to Discord, replacing any previous account', async () => {
  const profileId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
  const token = newToken();
  await database
    .statement(
      'INSERT INTO legacy_tickets(token_hash, legacy_user_id, profile, history, expires_at) VALUES (?, ?, ?, ?, unixepoch() + 600)',
      await sha256(token),
      'legacy-user',
      JSON.stringify({
        id: profileId,
        name: 'OldName',
        skinHash: 'a'.repeat(64),
        skinModel: 'slim',
        createdAt: 1700000000,
      }),
      JSON.stringify([{ previousName: 'First', newName: 'OldName', changedAt: 1700000100 }]),
    )
    .run();
  const attempts = await Promise.allSettled([
    linkLegacy(database, token, '333', 'player@example.com'),
    linkLegacy(database, token, '333', 'player@example.com'),
  ]);
  assert.equal(attempts.filter((result) => result.status === 'fulfilled').length, 1);
  const rejected = attempts.find((result) => result.status === 'rejected') as PromiseRejectedResult;
  assert.equal(rejected.reason.code, 'MigrationExpired');
  const account = harness.sqlite
    .prepare("SELECT id, legacy_user_id, discord_email, created_at FROM accounts WHERE discord_id = '333'")
    .get()!;
  assert.equal(account.id, profileId);
  assert.equal(account.legacy_user_id, 'legacy-user');
  assert.equal(account.discord_email, 'player@example.com');
  assert.equal(account.created_at, 1700000000);
  const profile = (await database.profileForDiscord('333'))!;
  assert.equal(profile.name, 'OldName');
  assert.equal(profile.skin_model, 'slim');
  assert.equal(
    harness.sqlite.prepare('SELECT previous_name FROM name_history WHERE profile_id = ?').get(profileId)!
      .previous_name,
    'First',
  );
  assert.equal(harness.sqlite.prepare('SELECT count(*) AS n FROM legacy_tickets').get()!.n, 0);
  await assert.rejects(linkLegacy(database, token, '333', null), { code: 'MigrationExpired' });
});

test('rejects legacy links whose name is taken or whose account is already linked', async () => {
  await database.register('444', 'TakenName');
  const ticket = async (name: string, userId: string) => {
    const token = newToken();
    await database
      .statement(
        'INSERT INTO legacy_tickets(token_hash, legacy_user_id, profile, history, expires_at) VALUES (?, ?, ?, ?, unixepoch() + 600)',
        await sha256(token),
        userId,
        JSON.stringify({
          id: 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff',
          name,
          skinHash: null,
          skinModel: 'default',
          createdAt: 1700000000,
        }),
        '[]',
      )
      .run();
    return token;
  };
  await assert.rejects(linkLegacy(database, await ticket('takenname', 'user-a'), '333', null), {
    code: 'UsernameTaken',
  });
  await linkLegacy(database, await ticket('FreshName', 'user-b'), '333', null);
  await assert.rejects(linkLegacy(database, await ticket('FreshName', 'user-c'), '444', null), {
    code: 'LegacyAlreadyLinked',
  });
  await assert.rejects(linkLegacy(database, await ticket('FreshName', 'user-b'), '444', null), {
    code: 'LegacyAlreadyLinked',
  });
});
