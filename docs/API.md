# Auth API

Servicio de autenticación y autorización en ASP.NET Core 10 (controllers), Identity, EF Core + SQLite.
Todas las rutas de negocio cuelgan de `/api/v1`. Las respuestas de error son ProblemDetails (RFC 9457).

- Documentación interactiva (solo `Development`): `/scalar/v1` · OpenAPI: `/openapi/v1.json`
- Claves públicas JWT: `GET /.well-known/jwks.json`
- Salud: `GET /health/live` (proceso) · `GET /health/ready` (incluye la base de datos)

## 1. Dos formas de autenticarse

| Cliente | Mecanismo | Cómo |
|---|---|---|
| SPA web | Cookie `__Host-auth` (HttpOnly, Secure, SameSite=Strict) + antiforgery | `login?useCookies=true` |
| Apps nativas / servicios | `Authorization: Bearer <JWT>` + refresh token opaco | `login` (por defecto) |

Por request se usa **un solo** esquema: si llega el header `Authorization` se valida como Bearer y la cookie
se ignora; si no, se usa la cookie. Ambos apuntan a una sesión en la base de datos, así que **cualquier
revocación es inmediata** (como máximo 30 s de cache, y la cache se invalida en cada revocación).

### 1.1 Flujo SPA (cookie)

```
GET  /api/v1/auth/antiforgery                       → { token, headerName: "X-XSRF-TOKEN" } + cookie __Host-xsrf
POST /api/v1/auth/login?useCookies=true             (header X-XSRF-TOKEN: token)
     → 200 { requiresMfa:false, user } + Set-Cookie __Host-auth
     → 200 { requiresMfa:true, mfaToken }            → POST /auth/login/mfa?useCookies=true (con X-XSRF-TOKEN)
GET  /api/v1/auth/antiforgery                       ← pedir un token NUEVO: está atado a la identidad
POST/PUT/PATCH/DELETE ...                           (siempre con X-XSRF-TOKEN)
POST /api/v1/auth/logout                            → 204, borra la cookie
```

- `fetch(..., { credentials: "include" })`. El navegador nunca ve tokens: no hay nada que robar con XSS
  desde `localStorage`.
- Sin `X-XSRF-TOKEN` válido, cualquier método no seguro autenticado por cookie responde **403
  `ANTIFORGERY_INVALID`** (también `login`/`login/mfa` con `useCookies=true`, contra login CSRF).
- La cookie se desliza con el uso (30 días de inactividad) y nunca supera el tope absoluto de la sesión (90 días).

**Requisito de despliegue:** la SPA y la API deben ser *same-site* (mismo dominio registrable, p.ej.
`app.example.com` y `api.example.com`, o la API detrás de un reverse proxy/YARP en el mismo origen). Con
`SameSite=Strict` la cookie no viaja en requests cross-site. Configurar `Cors:AllowedOrigins` con los orígenes
exactos de la SPA (nunca `*`).

### 1.2 Flujo nativo (Bearer)

```
POST /api/v1/auth/login            → 200 { requiresMfa:false, tokens: { accessToken, accessTokenExpiresAt,
                                                                       refreshToken, refreshTokenExpiresAt, tokenType } }
GET  ...  Authorization: Bearer <accessToken>     (10 min)
POST /api/v1/auth/refresh { refreshToken }       → par nuevo (rotación en cada uso)
```

- **Access token**: JWT ES256, `typ: at+jwt`, `kid`, `iss`, `aud`, `sub`, `sid`, `jti`, `amr`, `email_verified`.
  Los roles **no** viajan en el token: los permisos se resuelven en el servidor y los cambios aplican sin
  volver a iniciar sesión. Terceros pueden validarlo con el JWKS.
- **Refresh token**: opaco (32 bytes), en la DB solo su SHA-256. Rota en cada uso; ventana deslizante de 30 días
  y tope absoluto de 90 días.
  - Refrescos concurrentes con el mismo token durante **3 min** reciben el mismo par (gracia).
  - Reusar un token ya rotado **después** de la gracia se considera robo: se revoca la sesión entera.
- Las requests Bearer no necesitan antiforgery.

### 1.3 MFA (TOTP)

1. `POST /account/mfa/setup` → `{ sharedKey, otpAuthUri }` (el cliente genera el QR).
2. `POST /account/mfa/enable { code }` → `{ codes: [...10 recovery codes] }` — se muestran **una sola vez**.
3. En el login la respuesta trae `{ requiresMfa: true, mfaToken }` (vence en 5 min, uso único) y se completa con
   `POST /auth/login/mfa { mfaToken, code }` o `{ mfaToken, recoveryCode }` (exactamente uno). Usar el mismo
   `useCookies` en los dos pasos.

Cada código TOTP sirve una sola vez. Los fallos de MFA suman al mismo contador de lockout que la contraseña.

## 2. Endpoints

| Método | Ruta | Acceso | Rate limit |
|---|---|---|---|
| POST | `/auth/register` | anónimo | strict |
| POST | `/auth/confirm-email` | anónimo | strict |
| POST | `/auth/resend-confirmation` | anónimo | strict |
| GET | `/auth/antiforgery` | anónimo | — |
| POST | `/auth/login?useCookies=` | anónimo (+antiforgery si cookies) | login |
| POST | `/auth/login/mfa?useCookies=` | anónimo (+antiforgery si cookies) | mfa |
| POST | `/auth/refresh` | anónimo | refresh |
| POST | `/auth/forgot-password` | anónimo | strict |
| POST | `/auth/reset-password` | anónimo | strict |
| POST | `/auth/logout` | autenticado | — |
| POST | `/auth/logout-all` | autenticado | — |
| GET | `/account/me` | autenticado | — |
| POST | `/account/change-password` | verificado | strict |
| GET | `/account/mfa` | verificado | — |
| POST | `/account/mfa/setup` · `enable` · `disable` · `recovery-codes` | verificado | mfa (verificaciones) |
| GET | `/account/sessions` | verificado | — |
| DELETE | `/account/sessions/{id}` | verificado | — |
| GET | `/admin/users?search&page&pageSize` · `/admin/users/{id}` | `users.read` | — |
| POST | `/admin/users/{id}/lock` · `/unlock` | `users.manage` | — |
| PUT | `/admin/users/{id}/roles` | `roles.assign` | — |
| GET | `/admin/users/{id}/sessions` | `sessions.read.any` | — |
| DELETE | `/admin/sessions/{id}` | `sessions.revoke.any` | — |
| GET | `/admin/roles` · `/admin/roles/{id}` · `/admin/permissions` | `roles.read` | — |
| POST/PUT/DELETE | `/admin/roles[/{id}]` | `roles.manage` | — |
| GET | `/admin/audit?userId&type&from&to&page&pageSize` | `audit.read` | — |

Todo endpoint sin atributos exige **usuario autenticado con email verificado** (fallback policy); un anónimo
recibe 401 incluso en rutas inexistentes. Además hay un límite global de 100 requests/min por IP.

Respuestas que nunca revelan si un email existe: `register` (202), `resend-confirmation` (202),
`forgot-password` (202) y `login` (401 `INVALID_CREDENTIALS` genérico, con tiempo constante). `login` solo
responde 403 `EMAIL_NOT_CONFIRMED` si la contraseña es correcta.

## 3. Errores

```json
{
  "type": "https://tools.ietf.org/html/rfc9110#section-15.5.2",
  "title": "Unauthorized",
  "status": 401,
  "detail": "The access token has expired.",
  "code": "TOKEN_EXPIRED",
  "traceId": "00-…"
}
```

Los 422 agregan `errors: { campo: [mensajes] }`. Los 429 agregan el header `Retry-After`.

| Código | Status | Cuándo |
|---|---|---|
| `VALIDATION_FAILED` | 422 | Body inválido (FluentValidation) |
| `BAD_REQUEST` | 400 | Body ausente o JSON mal formado |
| `PASSWORD_TOO_WEAK` / `PASSWORD_BREACHED` | 422 | Política de contraseña / aparece en HIBP |
| `INVALID_CREDENTIALS` | 401 / 400 | Login fallido (401); contraseña actual incorrecta en cambio de contraseña o MFA (400) |
| `EMAIL_NOT_CONFIRMED` | 403 | Login con contraseña correcta y email sin confirmar |
| `MFA_INVALID` | 401 / 400 | Código o `mfaToken` inválido (401 en login, 400 en gestión de MFA) |
| `AUTH_HEADER_MISSING` | 401 | Sin credenciales |
| `TOKEN_INVALID` / `TOKEN_EXPIRED` | 401 | JWT mal formado, firma/alg/iss/aud/typ inválidos / vencido |
| `SESSION_REVOKED` | 401 | La sesión del token o cookie fue revocada o venció |
| `REFRESH_INVALID` | 401 | Refresh token inválido, vencido o reusado |
| `INVALID_TOKEN` | 400 | Token de confirmación o reset inválido o vencido |
| `ANTIFORGERY_INVALID` | 403 | Falta o no coincide `X-XSRF-TOKEN` |
| `FORBIDDEN` | 403 | Falta el permiso |
| `NOT_FOUND` / `CONFLICT` | 404 / 409 | Recurso inexistente (o ajeno) / regla de negocio |
| `RATE_LIMITED` | 429 | Límite excedido |
| `INTERNAL_ERROR` | 500 | Error inesperado (detalle solo en Development) |

## 4. Configuración y despliegue

Configuración en `src/Auth.Api/appsettings.json`; todas las secciones se validan al arrancar.
Secretos **nunca** en el repo:

```bash
dotnet user-secrets --project src/Auth.Api set "Email:Smtp:User" "..."
dotnet user-secrets --project src/Auth.Api set "Email:Smtp:Password" "..."
```

En producción usar variables de entorno (`Email__Smtp__Password`, etc.).

- **Claves JWT**: PEM PKCS#8 EC P-256 en `Jwt:SigningKeys[]` (`Kid`, `Path`, `Active`). En Development se
  generan solas (`Jwt:GenerateMissingKeys`). Para generar una de producción:
  `openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out jwt-prod-1.pem`.
  **Rotación**: agregar la clave nueva como `Active` y dejar la anterior como no activa al menos 10 min (vida
  del access token); después quitarla.
- **Data Protection** (`DataProtection:KeysPath`): protege cookies, tokens de email, challenge MFA y la clave
  TOTP. En Windows + Production se cifran con DPAPI; en Linux configurar `ProtectKeysWithCertificate`. Perder
  estas claves invalida cookies, links de email pendientes y obliga a reconfigurar MFA.
- **Proxy inverso**: `Network:TrustProxy=true` y `Network:KnownProxies`/`KnownNetworks`. Sin esto, el header
  `X-Forwarded-For` se ignora (la IP para rate limiting y auditoría es la de la conexión).
- **Email**: `Email:Provider` = `Smtp` (producción), `Pickup` (escribe `.eml` en `mail/`, desarrollo) o `Logging`.
- **Primer administrador**: registrar y confirmar la cuenta, después
  `dotnet run --project src/Auth.Api -- seed-admin --email admin@example.com`, o configurar `Seed:AdminEmail`
  (se aplica al arrancar).
- **Una sola instancia**: rate limiting, cache de sesiones/permisos, gracia de refresh y anti-replay viven en
  memoria. Para escalar horizontalmente mover esa cache a Redis y la base a PostgreSQL.

## 5. Desarrollo

```bash
dotnet build
dotnet test
dotnet run --project src/Auth.Api --launch-profile https
dotnet ef migrations add <Nombre> --project src/Auth.Infrastructure --startup-project src/Auth.Api --output-dir Persistence/Migrations
```

`dotnet ef` está como herramienta local (`dotnet tool restore`).
