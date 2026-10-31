# Desplegar Discord + D1 + R2

Este procedimiento publica el código con Wrangler y mantiene la web en el hosting actual. No requiere Supabase. Los recursos, secretos y cuentas reales no se crean desde los tests.

## 1. Preparar Discord

En [Discord Developer Portal](https://discord.com/developers/applications), creá una aplicación o usá la de CubicLauncher.

Anotá:

- **Application ID** → `DISCORD_CLIENT_ID`.
- **Client Secret** de OAuth2 → secreto `DISCORD_CLIENT_SECRET`.

En OAuth2 → Redirects agregá exactamente:

```text
https://auth.cubiclauncher.org/discord/callback
```

No hace falta bot ni permisos especiales: el login solo pide el scope `identify`.

## 2. Crear D1 y R2

Desde `CubAuth`, con Node 24.12+ y npm:

```sh
npm ci
npx wrangler login
npx wrangler d1 create cubauth
npx wrangler r2 bucket create cubicskins
```

Si ya creaste esos recursos, reutilizalos y obtené su identificación desde Cloudflare. R2 debe estar habilitado en la cuenta.

En `wrangler.jsonc`, reemplazá:

- `d1_databases[0].database_id`: el UUID real que devolvió `d1 create`.
- `DISCORD_CLIENT_ID`: el Application ID de Discord.
- `r2_buckets[0].bucket_name`: el nombre real del bucket (por ejemplo `cubicskins`).

Los bindings se llaman **DB** y **SKINS**; no cambies esos nombres. Verificá los dominios:

```json
{
  "PUBLIC_URL": "https://auth.cubiclauncher.org",
  "ACCOUNT_URL": "https://accounts.cubiclauncher.org",
  "WEB_ORIGINS": "https://accounts.cubiclauncher.org"
}
```

La ruta personalizada `auth.cubiclauncher.org` ya está declarada. La zona debe pertenecer a la cuenta de Cloudflare que uses. El bucket R2 puede permanecer privado: el Worker publica únicamente las texturas por su hash.

Aplicá la migración nueva a **D1**, sin ejecutar los archivos de `supabase/migrations`:

```sh
npx wrangler d1 migrations apply cubauth --remote
```

## 3. Guardar secretos y la firma de Minecraft

```sh
npx wrangler secret put DISCORD_CLIENT_SECRET
```

Pegá el valor cuando Wrangler lo pida. No lo guardes en Git ni en la web.

Si conservás la clave privada RSA del Worker actual y coincide con `SIGNING_PUBLIC_KEY` en `wrangler.jsonc`, mantené ese par. Si necesitás un par nuevo:

```sh
npm run keys
npx wrangler secret put SIGNING_PRIVATE_KEY < keys/private.pem
```

Copiá entonces el contenido de `keys/public.pem` a `SIGNING_PUBLIC_KEY` en `wrangler.jsonc` (como string JSON con saltos `\n`). El script de claves muestra material privado en tu terminal: no lo compartas ni lo publiques. Los archivos `keys/` están ignorados por Git.

Si la clave privada existente no está ya guardada en ese Worker, cargala con `wrangler secret put SIGNING_PRIVATE_KEY`. La clave pública y la privada deben pertenecer al mismo par.

## 4. Comprobar y publicar el Worker

```sh
npm run check
npm run deploy
```

`check` incluye TypeScript, pruebas del núcleo con SQLite, pruebas HTTP con D1/R2 locales y empaquetado de Wrangler sin publicar. Los tests usan Discord simulado; no crean usuarios ni envían mensajes a tu servidor.

Abrí `https://auth.cubiclauncher.org/`. Debe devolver JSON con los enlaces del frontend y `skinDomains` apuntando a `auth.cubiclauncher.org`.

Este despliegue cambia el backend activo: las credenciales y sesiones del sistema anterior dejan de funcionar. Las cuentas de Discord nuevas obtienen UUID nuevos. Mantené un respaldo de Supabase; no borres el proyecto anterior como parte de estos pasos.

## 5. Publicar la web

Desde `accounts.cubiclauncher.org`:

```sh
bun install --frozen-lockfile
bun run build
bun run test:unit -- --run
bun run test:e2e
```

Para los E2E necesitás Chromium instalado mediante Playwright, o `PLAYWRIGHT_CHROMIUM_EXECUTABLE` apuntando a un Chromium disponible. Si falta:

```sh
bunx playwright install chromium
```

En el proyecto actual de Vercel configurá:

```text
VITE_AUTH_API_URL=https://auth.cubiclauncher.org
```

Publicá la versión nueva del repositorio. `vercel.json` ya contiene el build, las rutas de la SPA y la CSP para las texturas nuevas. Si usás otro hosting estático, publicá `dist/` con fallback a `index.html` y aplicá los mismos headers de seguridad.

## 6. Verificación final

1. Entrá a `https://accounts.cubiclauncher.org/login` y elegí **Continuar con Discord**.
2. Autorizá Discord y elegí tu nombre de Minecraft.
3. Al completar el login, la página genera y muestra un token en **Entrar al launcher**. Copiá el nombre y usá el token como contraseña en el proveedor `https://auth.cubiclauncher.org` del launcher. Podés generar otro desde ese panel cuando lo necesites.
4. Verificá que el mismo token no permita un segundo ingreso y que generar otro invalide el anterior. El vencimiento de una hora corresponde al token de ingreso, no a la sesión ya iniciada.
5. Subí una skin y comprobá que la textura se sirva desde `auth.cubiclauncher.org/textures/…`.
6. Probá **Cerrar todas las sesiones**: deben quedar revocados los accesos de la web y del launcher.

El test de protocolo opcional usa un token recién generado y lo consume:

```sh
CUBAUTH_URL=https://auth.cubiclauncher.org CUBAUTH_USERNAME=TuNombre CUBAUTH_LAUNCHER_TOKEN=TOKEN_RECIEN_GENERADO npm run smoke
```

No publiques ese valor ni guardes el comando en archivos compartidos. El test comprueba ingreso, imposibilidad de reutilizar el token, join/hasJoined, firmas RSA, renovación y revocación.

## Solución de problemas

- **Discord rechaza el callback:** compará la URL registrada en OAuth2 con `PUBLIC_URL + /discord/callback`; deben coincidir exactamente.
- **Error de CORS:** `WEB_ORIGINS` debe contener el origen exacto del frontend, sin ruta. Para varios orígenes, separalos por comas.
- **Falta una tabla o un binding:** verificá `DB`, `SKINS`, el UUID de D1 y que aplicaste la migración con `--remote`.
- **Error de firma de Minecraft:** verificá que las claves RSA pública y privada coincidan.

Referencias: [OAuth2 de Discord](https://docs.discord.com/developers/topics/oauth2), [migraciones D1](https://developers.cloudflare.com/d1/reference/migrations/), [transacciones batch de D1](https://developers.cloudflare.com/d1/worker-api/d1-database/).