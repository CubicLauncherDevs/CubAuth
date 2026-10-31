# CubAuth

Servidor de cuentas y autenticación de Minecraft compatible con Yggdrasil / authlib-injector, ejecutado en Cloudflare Workers.

- **Discord OAuth2** identifica al usuario.
- **D1** almacena cuentas, perfiles, sesiones, historial de nombres y credenciales temporales.
- **R2** guarda las skins normalizadas. El Worker las publica en `/textures/:hash`; el bucket puede permanecer privado.
- **Web**: iniciar sesión con Discord, elegir nombre, gestionar skin y generar el token del launcher.
- **Launcher**: nombre de Minecraft + token de un uso que vence en una hora. Al entrar se emite una sesión Yggdrasil independiente.

## Despliegue

Seguí [DEPLOY.md](./DEPLOY.md), incluyendo Discord, D1, R2, secretos, frontend y comprobación final.

## Desarrollo

Requiere Node 24.12 o posterior y npm. Para el frontend se usa Bun.

```sh
npm ci
cp .dev.vars.example .dev.vars
npx wrangler d1 migrations apply cubauth --local
npm run dev
```

Completá `.dev.vars` con tu aplicación de desarrollo de Discord y registrá `http://localhost:8787/discord/callback` como redirect OAuth. El frontend local usa `VITE_AUTH_API_URL=http://localhost:8787`.

## Comprobaciones

```sh
npm run test:core
npm run typecheck
npm test
npx wrangler deploy --dry-run
```

`test:core` ejecuta los módulos reales de autenticación sobre SQLite y un adaptador con la misma semántica transaccional de D1. `npm test` añade pruebas HTTP con Workers, D1 y R2 locales, OAuth simulado, firmas RSA y normalización PNG. No usa Discord ni Cloudflare de producción.

## Contratos

- `POST /discord/start`: challenge SHA-256 del secreto generado por la pestaña.
- `GET /discord/callback`: valida y consume el state, consulta Discord y devuelve a la web un ticket de cinco minutos.
- `POST /discord/exchange`: consume el ticket con el secreto de la pestaña; entrega una sesión web o un permiso de registro de diez minutos.
- `POST /discord/register`: elige el nombre y finaliza el registro.
- `POST /account/launcher-token`: exige sesión web y membresía; genera un token de una hora. Generar otro invalida el anterior.
- `POST /authserver/authenticate`: consume el token y crea la sesión del launcher en una sola transacción.
- `POST /account/signout-all`: revoca sesiones web, sesiones del launcher y tokens pendientes.
- La web guarda la sesión en la cookie `cubauth_session` (`HttpOnly`, `Secure`, `SameSite=Lax`, ocho horas). Se emite al intercambiar el ticket de Discord, se rota al renovar o cambiar el nombre y se borra al salir. Los endpoints web aceptan también `Authorization: Bearer`; el frontend debe usar `credentials: 'include'` y la API responde con `Access-Control-Allow-Credentials: true`.
- Las rutas de perfiles, join/hasJoined, refresh, validate, invalidate y skins conservan el protocolo del launcher.
- Las sesiones web duran ocho horas; las del launcher usan `TOKEN_TTL_SECONDS` (por defecto quince días). El vencimiento del token de ingreso no corta la sesión del juego.
- Los secretos de Discord solo existen en el Worker. D1 almacena hashes de las credenciales, nunca los tokens en claro.

## Cambio desde el sistema anterior

La nueva instalación **no importa cuentas ni sesiones de Supabase**. El Worker deja de consultar ese servicio y ya no permite registro ni acceso con email/contraseña. Las cuentas nuevas reciben UUID nuevos: no conservan inventarios/permisos que un servidor de Minecraft vincule al UUID anterior.

El directorio `supabase/migrations` se conserva como historial del esquema anterior; no se ejecuta en D1 ni interviene en el servicio. Tampoco se usan los archivos del panel antiguo de `public`. Conservá un respaldo del sistema anterior antes del corte; no es necesario borrar el proyecto anterior para desplegar.

Para deshabilitar una cuenta nueva, poné `accounts.disabled = 1` en D1. Las comprobaciones de sesión lo respetan inmediatamente.
