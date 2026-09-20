'use strict';
const $ = id => document.getElementById(id);
let session = null;
let working = false;

// Supabase confirmation redirects may contain credentials. The panel does not use them.
if (location.hash.includes('access_token=') || location.hash.includes('error=')) {
  const params = new URLSearchParams(location.hash.slice(1));
  $('notice').textContent = params.get('error_description') || 'Confirmación recibida. Ya podés iniciar sesión.';
  history.replaceState(null, '', location.pathname);
}
$('server-url').textContent = `${location.origin}/`;

function notice(message, error = false) {
  $('notice').textContent = message;
  $('notice').classList.toggle('error', error);
}

async function api(path, options = {}) {
  const response = await fetch(path, { ...options, credentials: 'omit' });
  const body = response.status === 204 ? null : await response.json();
  if (!response.ok) {
    const details = body?.details;
    const diagnostic = details?.service === 'supabase'
      ? [details.operation, details.upstreamStatus && `HTTP ${details.upstreamStatus}`, details.upstreamCode].filter(Boolean).join(' · ')
      : '';
    throw new Error(`${body?.errorMessage || 'No se pudo completar la solicitud.'}${diagnostic ? ` [${diagnostic}]` : ''}`);
  }
  return body;
}

function post(path, body) {
  return api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}

async function action(callback) {
  if (working) return;
  working = true;
  document.querySelectorAll('button').forEach(button => { button.disabled = true; });
  notice('Procesando…');
  try { await callback(); }
  catch (error) { notice(error.message, true); }
  finally {
    working = false;
    document.querySelectorAll('button').forEach(button => { button.disabled = false; });
  }
}

function tab(register) {
  $('login-form').hidden = register;
  $('register-form').hidden = !register;
  $('login-tab').setAttribute('aria-pressed', String(!register));
  $('register-tab').setAttribute('aria-pressed', String(register));
}
$('login-tab').onclick = () => tab(false);
$('register-tab').onclick = () => tab(true);
tab(location.hash === '#register');

async function showSkin() {
  const profile = await api(`/sessionserver/session/minecraft/profile/${session.selectedProfile.id}`);
  const property = profile.properties.find(item => item.name === 'textures');
  const skin = JSON.parse(atob(property.value)).textures.SKIN;
  $('skin-preview').hidden = !skin;
  if (skin) $('skin-preview').src = skin.url;
  else $('skin-preview').removeAttribute('src');
  $('skin-form').elements.model.value = skin?.metadata?.model === 'slim' ? 'slim' : '';
}

$('login-form').onsubmit = event => {
  event.preventDefault();
  action(async () => {
    const form = new FormData(event.target);
    session = await post('/authserver/authenticate', {
      username: form.get('username'), password: form.get('password'),
      clientToken: crypto.randomUUID(), agent: { name: 'Minecraft', version: 1 },
    });
    event.target.reset();
    $('auth').hidden = true;
    $('profile').hidden = false;
    $('player-name').textContent = session.selectedProfile.name;
    $('player-id').textContent = session.selectedProfile.id;
    notice('Sesión iniciada.');
    await showSkin();
  });
};

$('register-form').onsubmit = event => {
  event.preventDefault();
  action(async () => {
    const body = Object.fromEntries(new FormData(event.target));
    await post('/account/register', body);
    event.target.reset();
    tab(false);
    notice('Registro recibido. Revisá tu correo para confirmar la cuenta si la confirmación está activada.');
  });
};

$('skin-form').onsubmit = event => {
  event.preventDefault();
  action(async () => {
    const form = new FormData(event.target);
    if (form.get('file').size > 128 * 1024) throw new Error('El PNG supera los 128 KiB.');
    await api(`/api/user/profile/${session.selectedProfile.id}/skin`, {
      method: 'PUT', headers: { Authorization: `Bearer ${session.accessToken}` }, body: form,
    });
    await showSkin();
    notice('Skin guardada. Volvé a entrar al servidor para verla actualizada.');
  });
};

$('delete-skin').onclick = () => action(async () => {
  await api(`/api/user/profile/${session.selectedProfile.id}/skin`, {
    method: 'DELETE', headers: { Authorization: `Bearer ${session.accessToken}` },
  });
  await showSkin();
  notice('Skin eliminada del perfil.');
});

$('logout').onclick = () => action(async () => {
  await post('/authserver/invalidate', { accessToken: session.accessToken });
  session = null;
  $('profile').hidden = true;
  $('auth').hidden = false;
  $('skin-preview').removeAttribute('src');
  notice('Sesión cerrada.');
});
