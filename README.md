# CubAuth

Servidor Yggdrasil para **Cloudflare Workers + Supabase**, con cuentas propias,
sesiones revocables y skins. Incluye un panel en `/account` y API compatible con
authlib-injector. TypeScript, Hono y Wrangler; no requiere un servidor Node en producción.

## Qué incluye

- Registro con correo y nombre de Minecraft; login por cualquiera de los dos.
- Contraseñas y confirmación de correo gestionadas por Supabase Auth.
- Un perfil permanente por cuenta, UUID v4 y nombre único de 3–16 caracteres.
- `authenticate`, `refresh`, `validate`, `invalidate` y `signout`.
- `join`/`hasJoined` compartidos entre todas las instancias del Worker.
- Tokens aleatorios de 256 bits, almacenados como SHA-256, con renovación atómica.
- Hasta diez sesiones por cuenta; caducidad predeterminada de 15 días.
- Revocación de sesiones al cambiar la contraseña; comprobación de usuarios suspendidos.
- Skins clásicas/slim, consulta de perfiles y firmas RSA-SHA1 del protocolo.
- Panel de registro, login, subida y eliminación de skins.
- Límites de intentos en Postgres y limpieza horaria de registros caducados.

## 1. Instalar

Requisitos: Node.js 22.12+ y npm, una cuenta de Cloudflare y un **proyecto dedicado de Supabase**.

```bash
cd /tmp/cubauth
npm ci
```

El proyecto utiliza APIs criptográficas de Workers. El procesador de PNG es JavaScript;
no necesita binarios de imágenes en producción.

## 2. Preparar Supabase

1. Creá un proyecto y abrí **SQL Editor**.
2. Ejecutá una sola vez cada archivo, en este orden:

   ```text
   supabase/migrations/202609200001_cubauth.sql
   supabase/migrations/202609200002_account_settings.sql
   ```

   Si ya instalaste la primera migración, ejecutá solamente la segunda. Agrega
   gestión de cuenta e historial sin borrar usuarios, perfiles ni UUIDs.

3. En **Authentication → Providers**, habilitá Email/password. Configurá una
   longitud mínima de contraseña de 10 caracteres. Decidí si querés confirmar correo.
4. Para confirmaciones de correo, configurá SMTP para tu despliegue y establecé:
   - **Site URL:** `https://TU_WORKER.workers.dev/account`
   - **Redirect URLs:** la misma URL; añadí `http://localhost:8787/account` para desarrollo.
5. Copiá la URL del proyecto y las claves de API desde la configuración de Supabase.

La migración crea el bucket público `skins`, tablas privadas en `cubauth` y
funciones `public.cubauth_*` accesibles **solo con la clave de servicio**. No añadas
`cubauth` a los esquemas expuestos de la Data API ni políticas públicas de escritura.
El esquema `public` debe seguir expuesto para llamar a las funciones.

**El trigger de creación de perfiles se aplica a cada nuevo usuario de Supabase.**
Requiere `raw_user_meta_data.username`; por eso este proyecto debe ser dedicado.
Los usuarios previos no se migran automáticamente. El registro del panel envía ese dato.

Para crear una cuenta desde el Admin API, incluí `user_metadata.username` y configurá
la confirmación del correo según tu flujo. El panel administrativo de Supabase permite
gestionar las cuentas y recuperar el acceso; CubAuth no incluye una página de recuperación.

## 3. Configuración y claves

Editá `vars` en `wrangler.jsonc`:

| Variable | Valor |
| --- | --- |
| `PUBLIC_URL` | URI raíz de tu Worker, por ejemplo `https://cubauth.mi-cuenta.workers.dev` |
| `SUPABASE_URL` | `https://TU_PROYECTO.supabase.co` |
| `SERVER_NAME` | Nombre mostrado en launchers |
| `ALLOW_REGISTRATION` | `true` o `false` para el registro del Worker |
| `TOKEN_TTL_SECONDS` | 60–2592000; predeterminado 1296000 |

Generá una clave RSA persistente:

```bash
npm run keys
```

Se crean `keys/private.pem` y `keys/public.pem`. El comando también muestra sus
valores escapados para `.dev.vars`. No sobrescribe claves existentes.
Guardá las claves: deben ser las mismas para todas las instancias del servicio.

### Desarrollo local

Copiá `.dev.vars.example` a `.dev.vars` y completá las cuatro variables:

```dotenv
SUPABASE_ANON_KEY="..."
SUPABASE_SERVICE_ROLE_KEY="..."
SIGNING_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
SIGNING_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
```

Se admiten tanto las claves antiguas `anon`/`service_role` como las nuevas
`sb_publishable_...`/`sb_secret_...`. La clave de servicio nunca se envía al navegador.
`.dev.vars`, `keys/` y los archivos `.env` están excluidos de Git.

Con `PUBLIC_URL` en `http://localhost:8787`:

```bash
npm run dev
```

Abrí `http://localhost:8787/account`. El Worker local se conecta al proyecto Supabase
que configuraste; usá un proyecto de desarrollo para esas pruebas.

## 4. Desplegar en Cloudflare

### Panel Vue en Vercel

El nuevo panel está en el repositorio `CubicLauncherDevs/AccountsFrontend` y se
publica en `https://accounts.cubiclauncher.org`. El Worker continúa atendiendo la API
Yggdrasil en `https://auth.cubiclauncher.org`.

Variables adicionales de `wrangler.jsonc`:

| Variable | Valor de producción |
| --- | --- |
| `ACCOUNT_URL` | `https://accounts.cubiclauncher.org` |
| `WEB_ORIGINS` | `https://accounts.cubiclauncher.org` |

`WEB_ORIGINS` admite orígenes exactos separados por comas. Habilita preflights para
`Content-Type` y `Authorization`, sin cookies cross-origin. Los errores también
incluyen los encabezados CORS para los orígenes permitidos. Los launchers nativos
sin `Origin` siguen funcionando.

Con `ACCOUNT_URL` configurado, `GET /account` redirige al panel nuevo y los enlaces
de registro/confirmación apuntan a `/register` y `/login` del frontend. En Supabase
configurá Site URL con `https://accounts.cubiclauncher.org/login` y permití ambas
Redirect URLs: `https://accounts.cubiclauncher.org/login` y
`https://accounts.cubiclauncher.org/account`.
Sin `ACCOUNT_URL`, sigue disponible el panel HTML de respaldo en el Worker.

El frontend usa un proxy local de Vite durante el desarrollo. Para un frontend
local o preview que consulte la API directamente, agregá su origen exacto a
`WEB_ORIGINS`. El dominio propio de la petición siempre se acepta.

### Publicar la API

Establecé primero `PUBLIC_URL` y `SUPABASE_URL` con los valores de producción.

```bash
npx wrangler login
npx wrangler secret put SUPABASE_ANON_KEY
npx wrangler secret put SUPABASE_SERVICE_ROLE_KEY
npx wrangler secret put SIGNING_PRIVATE_KEY < keys/private.pem
npx wrangler secret put SIGNING_PUBLIC_KEY < keys/public.pem
npm run deploy
```

Wrangler puede pedir crear el Worker al configurar el primer secreto. Las primeras
dos órdenes `secret put` solicitan el valor de forma interactiva.

El dominio `workers.dev` funciona sin dominio propio. Si añadís un dominio personalizado,
actualizá `PUBLIC_URL` y las URLs de redirección de Supabase. No apliques challenges HTML
de Cloudflare a las rutas de la API: los clientes de Minecraft esperan JSON o HTTP 204.

Comprobaciones iniciales:

```bash
curl https://TU_WORKER.workers.dev/
```

Debe responder metadatos JSON, incluyendo `signaturePublickey` y `skinDomains`.
Después abrí `/account`, creá una cuenta, confirmá el correo y subí tu skin.

## 5. Conectar CubicLauncher y Minecraft

URI del proveedor Yggdrasil:

```text
https://TU_WORKER.workers.dev/
```

Si tu launcher pide por separado el authserver, usá
`https://TU_WORKER.workers.dev/authserver` como prefijo de `authenticate`, etc.
Si añade `/authserver/authenticate` automáticamente, proporcioná solo la URI raíz.

El launcher debe usar la respuesta real de `authenticate`: `accessToken`,
`clientToken`, `selectedProfile.id` y `selectedProfile.name`. El UUID tiene 32 caracteres,
sin guiones. Los tokens de Supabase no sustituyen al `accessToken` de Yggdrasil.

Al iniciar el juego, añadí este argumento JVM **antes de la clase principal**:

```text
-javaagent:/ruta/authlib-injector.jar=https://TU_WORKER.workers.dev/
```

El servidor Minecraft también debe confiar en este proveedor:

```bash
java -javaagent:authlib-injector.jar=https://TU_WORKER.workers.dev/ -jar server.jar nogui
```

En `server.properties`:

```properties
online-mode=true
enforce-secure-profile=false
```

`enforce-secure-profile=false` aplica a versiones que ofrecen esta opción: CubAuth
no emite certificados para la firma de mensajes del chat. La autenticación de sesión
permanece activada con `online-mode=true`.

Usá una versión de authlib-injector compatible con tu versión de Minecraft.
Las cuentas funcionan en servidores que confíen en CubAuth, no como cuentas Microsoft.
Cambiar un mundo desde UUID offline u otro proveedor requiere migrar los datos de jugadores:
CubAuth asigna UUID nuevos y estables, independientes del nombre.

## API

Todas las rutas son relativas a la URI raíz. Los cuerpos son JSON salvo la subida de PNG.
Los errores usan `{ "error": "...", "errorMessage": "..." }`.

| Método | Ruta | Comportamiento |
| --- | --- | --- |
| GET | `/` | Metadatos, clave pública y dominios de texturas |
| POST | `/account/register` | `{email, username, password}`; HTTP 202 |
| GET | `/account/me` | Detalles privados del titular, confirmación del correo e historial; requiere Bearer |
| POST | `/account/username` | `{username, currentPassword}`; preserva UUID, registra historial y devuelve una sesión nueva |
| POST | `/account/email` | `{email, currentPassword}`; solicita cambio mediante Supabase Auth |
| POST | `/account/password` | `{currentPassword, newPassword}`; revoca sesiones anteriores y devuelve una nueva |
| POST | `/account/resend-verification` | `{email}`; reenvío de confirmación, respuesta genérica HTTP 202 |
| POST | `/authserver/authenticate` | Credenciales → sesión y perfil |
| POST | `/authserver/refresh` | Rota el token conservando `clientToken` |
| POST | `/authserver/validate` | 204 válido; 403 inválido |
| POST | `/authserver/invalidate` | Revoca un token; 204 incluso si ya no existe |
| POST | `/authserver/signout` | Usuario/contraseña → revoca todas sus sesiones |
| POST | `/sessionserver/session/minecraft/join` | Registra `serverId` durante 30 segundos |
| GET | `/sessionserver/session/minecraft/hasJoined` | Perfil firmado o 204 |
| GET | `/sessionserver/session/minecraft/profile/:uuid` | Perfil; `?unsigned=false` para firmas |
| POST | `/api/profiles/minecraft` | Array de hasta 100 nombres → perfiles existentes |
| PUT | `/api/user/profile/:uuid/skin` | `multipart/form-data`: `file` y `model` |
| DELETE | `/api/user/profile/:uuid/skin` | Quita la skin del perfil |

Para subir o eliminar una skin: `Authorization: Bearer ACCESS_TOKEN`.
`model` es vacío/`default` para clásico o `slim` para brazos finos.

### Skins y firmas

- PNG no entrelazados de 64×64 o 64×32; máximo 128 KiB; hasta 8 bits por canal.
- Paletas y transparencia admitidas. Las skins 64×32 requieren modelo clásico.
- Se limita la descompresión, se eliminan metadatos y se regenera RGBA8.
- El nombre del archivo es el SHA-256 del PNG resultante, sin extensión.
- Los archivos públicos se sirven desde Supabase Storage como `image/png`.
- Las propiedades se firman sobre su valor en Base64 con RSA PKCS#1 v1.5 + SHA-1,
  como exige este protocolo; los hashes de tokens/archivos usan SHA-256.
- Al quitar/cambiar una skin se actualiza el perfil. Los archivos anteriores permanecen
  en Storage para mantener referencias y cachés existentes; la limpieza de registros
  caducados no elimina archivos. Podés gestionar esa retención desde Supabase.
- No incluye capas, skins HD ni múltiples perfiles por cuenta.

### Gestión de cuenta

El login traduce los códigos de Supabase Auth `user_banned` y `email_not_confirmed`
a `AccountBanned` y `EmailNotConfirmed` (HTTP 403). No emite tokens Yggdrasil en
ninguno de esos casos. El panel muestra el estado correspondiente en lugar de
confundirlo con una contraseña incorrecta. Se respetan las suspensiones configuradas
en Supabase Auth y su opción **Confirm email**.

Las operaciones de nombre, correo y contraseña requieren el token Yggdrasil de la
cuenta **y su contraseña actual**. Supabase verifica la contraseña y realiza los
cambios de credenciales; la sesión temporal de Supabase nunca sale del Worker.

La migración `202609200002_account_settings.sql` guarda cada cambio de nombre en
`cubauth.name_history`, asociado al UUID permanente del perfil. El historial es
privado, se conserva completo y `/account/me` devuelve los últimos 20 cambios.
No reconstruye nombres anteriores a su instalación. El login solo acepta el nombre
actual o el correo, no los nombres históricos.

Tras un cambio de nombre, las demás sesiones quedan temporalmente inválidas y
deben usar `/authserver/refresh`. Un token caducado o revocado sigue sin poder
renovarse. La pestaña que cambia el nombre recibe su token renovado en la respuesta.

Los cambios de correo respetan la confirmación configurada por Supabase. Con
**Secure email change** activo, pueden requerir enlaces en el correo anterior y el
nuevo. `/account/me` expone el correo pendiente sin presentarlo como confirmado.
El estado de confirmación proviene de Supabase: si **Confirm email** está desactivado,
Supabase confirma automáticamente las cuentas nuevas. Activá esa opción y SMTP para
exigir verificación por correo.

### Límites

- Login/signout: 40 intentos por IP y 10 por cuenta cada 10 minutos, compartidos.
- Registro: 5 por IP por hora.
- Cambios de skin: 20 por cuenta cada 10 minutos.
- Cambios de cuenta: 10 por usuario cada 10 minutos, además del límite de reautenticación.
- Reenvíos de confirmación: 5 por IP por hora y 3 por dirección cada 10 minutos,
  además de los límites de correo de Supabase.
- Los límites y sesiones se guardan en Postgres, no en la memoria del Worker.
- `CF-Connecting-IP` es proporcionado por Cloudflare. En desarrollo local, sin ese
  encabezado, se utiliza `127.0.0.1`.
- Las peticiones nativas sin `Origin` están permitidas. Las peticiones del panel
  deben venir del mismo origen que la URL del Worker o de un origen exacto incluido
  en `WEB_ORIGINS`. `PUBLIC_URL` es la raíz de la API y `ACCOUNT_URL` la del panel.

## Diagnosticar errores de Supabase

Aunque las cuentas y contraseñas usan **Supabase Auth**, el registro también llama a
Postgres para limitar intentos. Las sesiones Yggdrasil y los perfiles necesitan las
tablas y funciones de la migración. Activar Auth por sí solo no instala esas funciones.

Las excepciones incluyen un diagnóstico en la respuesta y en los logs del Worker:

```json
{
  "error": "DatabaseFunctionMissing",
  "errorMessage": "Supabase cannot find the required CubAuth RPC...",
  "details": {
    "service": "supabase",
    "operation": "cubauth_rate_limit",
    "upstreamStatus": 404,
    "upstreamCode": "PGRST202"
  }
}
```

El panel también muestra operación, estado HTTP de Supabase y código. Los errores
no incluyen respuestas SQL completas, argumentos, contraseñas ni tokens.

| Excepción | Qué revisar |
| --- | --- |
| `DatabaseFunctionMissing` / `PGRST202` | Falta el RPC o PostgREST no lo encuentra en su caché. Ejecutá la migración si no está instalada. |
| `DatabaseSchemaMissing` | Faltan tablas, columnas o funciones. Revisá que la migración completa se haya aplicado en el proyecto correcto. |
| `DatabaseFunctionAmbiguous` | Existen varias versiones de un RPC con firmas incompatibles. Compará las funciones con la migración. |
| `DatabaseSchemaNotExposed` | Habilitá la Data API y exponé `public`; mantené `cubauth` privado. |
| `SupabaseKeyMissing` | Falta el secreto indicado en Cloudflare. |
| `SupabaseCredentialsInvalid` | Clave de otro proyecto, vencida o de tipo incorrecto. Usá `secret`/`service_role` para `SUPABASE_SERVICE_ROLE_KEY`. |
| `DatabasePermissionDenied` / `42501` | Revisá la clave de servicio y los permisos `EXECUTE` otorgados por la migración. |
| `SupabaseConnectionFailed` / HTTP 530 | Comprobá la Project URL, dominio y disponibilidad del proyecto. |
| `SupabaseTimeout` | La petición no respondió en 15 segundos. Revisá disponibilidad y conexión. |
| `SupabaseUnavailable` | Revisá si el proyecto está pausado, saturado o con errores de base de datos. |
| `SupabaseRateLimited` | Esperá antes de reintentar y revisá los límites del proyecto. |
| `SupabaseInvalidResponse` | Se recibió contenido que no es JSON. Revisá URL y proxies. |
| `DatabaseOperationFailed` | Consultá el código y la operación indicados en los logs de Supabase. |

Para comprobar si el primer RPC del registro existe, ejecutá en el SQL Editor:

```sql
select to_regprocedure('public.cubauth_rate_limit(text,integer,integer)');
```

Si devuelve `NULL`, falta la función en ese proyecto. Ejecutá una sola vez el archivo
`supabase/migrations/202609200001_cubauth.sql`. Si ya existe pero recibís `PGRST202`,
actualizá la caché de la API:

```sql
NOTIFY pgrst, 'reload schema';
```

## Pruebas

```bash
npm run check
```

Ejecuta TypeScript, pruebas en **workerd**, pruebas SQL en **PostgreSQL/PGlite** y
un empaquetado `wrangler deploy --dry-run`.

Las pruebas SQL ejecutan la migración real sobre esquemas mínimos de `auth` y
`storage`. Las respuestas HTTP de Supabase Auth/Storage están simuladas. Cubren
permisos, tokens, rotación, perfiles ajenos, expiración, cambios de contraseña,
firmas, procesamiento de PNG y flujo HTTP completo con las funciones SQL reales.
No requieren credenciales ni contactan un proyecto Supabase.

Después del despliegue, podés verificar la API real con una cuenta de prueba:

```bash
export CUBAUTH_URL="https://TU_WORKER.workers.dev"
export CUBAUTH_USERNAME="JugadorDePrueba"
read -rs -p "Contraseña: " CUBAUTH_PASSWORD; export CUBAUTH_PASSWORD
npm run smoke
unset CUBAUTH_PASSWORD
```

Opcionalmente, `CUBAUTH_SKIN=/ruta/skin.png` hace que esa prueba **cambie la skin de
la cuenta indicada**; `CUBAUTH_SKIN_MODEL=slim` selecciona brazos finos. Sin esa
variable no modifica skins. El script verifica firmas, rota/revoca su sesión y no
imprime credenciales. No sustituye una prueba real entrando a Minecraft.

Especificación: https://yushijinhun.github.io/authlib-injector/en/yggdrasil-server-technical-specification.html
