import assert from 'node:assert/strict';
import { randomUUID, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const base = process.env.CUBAUTH_URL?.replace(/\/$/, '');
const username = process.env.CUBAUTH_USERNAME;
const password = process.env.CUBAUTH_PASSWORD;
if (!base || !username || !password) throw new Error('Set CUBAUTH_URL, CUBAUTH_USERNAME and CUBAUTH_PASSWORD.');
const url = new URL(base);
if (url.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) throw new Error('Use HTTPS except for localhost.');
const tokens = new Set();

async function request(path, options = {}, expected = 200) {
  const res = await fetch(`${base}${path}`, { ...options, signal: AbortSignal.timeout(20000) });
  if (res.status !== expected) {
    // No request payload or upstream body in error output.
    throw new Error(`${options.method ?? 'GET'} ${path.split('?')[0]}: expected ${expected}, got ${res.status}`);
  }
  return res.status === 204 ? null : res.json();
}
const post = (path, body, expected = 200) => request(path, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
}, expected);

try {
  const metadata = await request('/');
  assert.ok(metadata.signaturePublickey);
  let session = await post('/authserver/authenticate', {
    username, password, clientToken: randomUUID(), agent: { name: 'Minecraft', version: 1 }, requestUser: true,
  });
  tokens.add(session.accessToken);
  assert.match(session.selectedProfile.id, /^[a-f0-9]{32}$/);
  await post('/authserver/validate', { accessToken: session.accessToken, clientToken: session.clientToken }, 204);
  console.log('PASS authenticate + validate');

  if (process.env.CUBAUTH_SKIN) {
    const form = new FormData();
    form.set('file', new Blob([await readFile(process.env.CUBAUTH_SKIN)], { type: 'image/png' }), 'skin.png');
    form.set('model', process.env.CUBAUTH_SKIN_MODEL ?? '');
    await request(`/api/user/profile/${session.selectedProfile.id}/skin`, {
      method: 'PUT', headers: { Authorization: `Bearer ${session.accessToken}` }, body: form,
    }, 204);
    console.log('PASS skin upload');
  }

  const serverId = randomUUID().replaceAll('-', '');
  await post('/sessionserver/session/minecraft/join', { accessToken: session.accessToken, selectedProfile: session.selectedProfile.id, serverId }, 204);
  const joined = await request(`/sessionserver/session/minecraft/hasJoined?${new URLSearchParams({ username: session.selectedProfile.name, serverId })}`);
  assert.equal(joined.id, session.selectedProfile.id);
  for (const property of joined.properties) {
    assert.ok(verify('RSA-SHA1', Buffer.from(property.value), metadata.signaturePublickey, Buffer.from(property.signature, 'base64')));
  }
  console.log('PASS join + hasJoined + RSA signatures');

  const previous = session.accessToken;
  session = await post('/authserver/refresh', { accessToken: previous, clientToken: session.clientToken });
  tokens.add(session.accessToken);
  assert.notEqual(session.accessToken, previous);
  await post('/authserver/validate', { accessToken: previous }, 403);
  await post('/authserver/validate', { accessToken: session.accessToken }, 204);
  await post('/authserver/invalidate', { accessToken: session.accessToken }, 204);
  await post('/authserver/validate', { accessToken: session.accessToken }, 403);
  console.log('PASS refresh + revocation');
} finally {
  for (const accessToken of tokens) {
    await post('/authserver/invalidate', { accessToken }, 204).catch(() => {
      console.error('Could not revoke a test session. Sign out all sessions when the service is available.');
    });
  }
}
