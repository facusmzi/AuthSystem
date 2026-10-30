# Decisiones de diseño

Registro de decisiones no cubiertas (o ajustadas) respecto de `PLAN.md`. Ante la duda se eligió la opción más segura.

## D-001 · Paquetes y licencias

| Paquete | Licencia |
|---|---|
| Microsoft.AspNetCore.* / Microsoft.EntityFrameworkCore.* / Microsoft.Extensions.* | MIT |
| Scalar.AspNetCore | MIT |
| FluentValidation | Apache 2.0 |
| Konscious.Security.Cryptography.Argon2 | MIT |
| MailKit | MIT |
| xunit.v3 | Apache 2.0 |
| NSubstitute | BSD-3-Clause |
| Shouldly | BSD-3-Clause |
| NetArchTest.Rules | MIT |

No se usan FluentAssertions (v8+ comercial) ni Duende.

## D-002 · Runner de tests: Microsoft.Testing.Platform

El SDK de .NET 10 ya no permite `dotnet test` con VSTest para proyectos xunit.v3; `global.json` activa
`"test": { "runner": "Microsoft.Testing.Platform" }`. Los proyectos de test son ejecutables (`OutputType=Exe`)
y no necesitan `Microsoft.NET.Test.Sdk` ni `xunit.runner.visualstudio`.

## D-003 · `Cache-Control: no-store` en todo `/api`

El plan lo pide para `/auth/*` y `/account/*`; se extiende a todo `/api` (incluye `/admin/*`, que también
devuelve datos sensibles).

## D-004 · Clases de opciones en Infrastructure

El plan ubica las `*Options` en `Auth.Api/Options`, pero los servicios de Infrastructure las consumen y
Infrastructure no puede depender de Api. Las opciones que usa Infrastructure viven en
`Auth.Infrastructure/Options`; solo las exclusivas del host (CORS, rate limiting, red, cookies) quedan en Api.
Para evitar colisiones con tipos de ASP.NET se renombraron: `AccountLockoutOptions` (sección `Lockout`),
`EmailTokenOptions` (sección `Tokens`), `KeyStorageOptions` (sección `DataProtection`) y
`UserSessionOptions` (sección `Sessions`).

## D-005 · Base de datos de tests en archivo temporal

Los tests de integración usan un archivo SQLite temporal por fixture (WAL activado) en lugar de
`:memory:` con conexión compartida: una única `SqliteConnection` no es thread-safe y el plan exige
tests de refrescos concurrentes (`Task.WhenAll`). El archivo se borra al liberar el fixture.

## D-006 · Interoperabilidad Argon2 verificada con RFC 9106

No hay Node disponible en el entorno para generar un hash con `node-argon2`. Se verifica la
implementación contra el vector oficial de RFC 9106 §5.3 y se testea el parseo del formato PHC que
emite `node-argon2` (`$argon2id$v=19$m=..,t=..,p=..$salt$hash`, base64 sin padding, también sin `v=`).

## D-007 · Data Protection protegida en producción

En Windows + `Production` las claves se cifran con DPAPI. En Linux hay que configurar
`ProtectKeysWithCertificate` en el despliegue (documentado en `docs/API.md`).

## D-008 · Whitelist beta: 202 sin revelar

Con `Features:BetaWhitelist` activo y un email fuera de la lista, el registro responde el mismo 202 que
un registro normal (no crea nada y audita `RegistrationRejectedWhitelist`). Se elige la variante que no
revela información por sobre el 403 explícito del original.

## D-009 · Emails encolados

`IEmailSender` encola en un `Channel` y un `BackgroundService` hace el envío real (Logging / Pickup / SMTP).
Así la latencia de `register`, `resend-confirmation` y `forgot-password` no depende de si la cuenta existe
ni de la latencia del SMTP. El proveedor `Logging` solo registra destinatario y asunto (el cuerpo lleva
tokens); en desarrollo se usa `Pickup`, que escribe `.eml` en `mail/` (ignorado por git).

## D-010 · Token providers con reloj inyectable

Confirmación de email (24 h) y reset (1 h) usan `TimedTokenProvider`, equivalente a
`DataProtectorTokenProvider` pero con `TimeProvider` (testeable) y tokens base64url. El token incluye el
security stamp, por lo que el de reset queda inválido tras usarse (uso único).

## D-011 · Validación de contraseña antes de mirar si el email existe

En el registro la política de contraseña (incluido HIBP) se evalúa primero, y en el camino "email
existente" se gasta un hash Argon2 equivalente: ni el código de estado ni la latencia revelan la cuenta.

## D-012 · Controllers en lugar de Minimal APIs

Por pedido explícito, la capa HTTP usa **controllers** (`[ApiController]`, rutas `api/v1/...`) en lugar de
Minimal APIs con `MapGroup`. El resto del plan no cambia. Equivalencias:
- `ValidationFilter<T>` (endpoint filter) → `ValidationFilter` global (`IAsyncActionFilter`) que ejecuta el
  `IValidator<T>` de cada argumento y responde 422.
- Errores de binding (body ausente / JSON inválido) → `InvalidModelStateResponseFactory` devuelve 400
  ProblemDetails con `code = BAD_REQUEST`.
- `.RequireRateLimiting(..)` / `.AllowAnonymous()` / `.RequirePermission(..)` → atributos
  `[EnableRateLimiting]`, `[AllowAnonymous]` y `[HasPermission]`.
- Los resultados `Result<T>` se convierten con `ToActionResult()`; los errores con `ProblemResult`, que
  serializa el tipo concreto (no se pierde `errors` en los 422) y agrega `traceId`.

## D-013 · Lockout propio en lugar de `SignInManager.CheckPasswordSignInAsync`

`CheckPasswordSignInAsync` consulta el esquema `TwoFactorRememberMe` para usuarios con MFA y usa
`DateTimeOffset.UtcNow`. Se usa `UserManager.CheckPasswordAsync` (que mantiene el rehash automático) más
`AccountLockout`, con la misma semántica de Identity (5 fallos → 15 min, contador compartido con MFA)
pero con `TimeProvider`. No se registra `SignInManager`.

## D-014 · El lockout por fallos no invalida sesiones activas

El validador de sesión rechaza usuarios **bloqueados por un administrador** (`LockoutEnd = MaxValue`), no
los bloqueados temporalmente por intentos fallidos: si no, un atacante podría cerrar las sesiones de la
víctima con 5 contraseñas incorrectas. El bloqueo de admin además revoca las sesiones (`UserLocked`).

## D-015 · Rutas inexistentes responden 401 a anónimos

La fallback policy también aplica cuando no hay endpoint, así que un anónimo recibe 401 en cualquier ruta
desconocida (no puede enumerar rutas); un usuario autenticado recibe 404.

## D-016 · Detección de reuso de refresh token

Se detecta el reuso del token inmediatamente anterior (`PreviousRefreshTokenHash`) fuera de la gracia de
3 min y se revoca la sesión. Si el token anterior aparece dentro de la gracia pero el par todavía no está en
cache (carrera con otra request que lo está rotando), se reintenta brevemente y, si no aparece, se devuelve
401 sin revocar.

## D-017 · Antiforgery fallido → 403 `ANTIFORGERY_INVALID`

El plan admite 400 o 403; se usa 403. El filtro es un `IAsyncAuthorizationFilter` global, así que corre
antes del binding/validación. El token antiforgery está atado a la identidad: la SPA debe pedir
`GET /api/v1/auth/antiforgery` al cargar, después del login y después del logout.

## D-018 · Reglas de administración

- Un admin no puede bloquearse a sí mismo (409) ni el último admin puede perder el rol `Admin` (409).
- `Admin` y `User` no se renombran ni se borran; `Admin` siempre conserva todos los permisos (409).
- El bloqueo de admin es indefinido (`LockoutEnd = MaxValue`), revoca todas las sesiones (`UserLocked`) y solo
  se levanta con `unlock`.
- `PermissionService` está en Infrastructure y se prueba como test de integración (necesita la DB real).

## D-019 · Contraseñas: códigos de error

- `change-password` con contraseña actual incorrecta → **400** `INVALID_CREDENTIALS` (no 401, para que la SPA
  no interprete que la sesión cayó). El fallo cuenta para el lockout: una sesión robada no sirve para adivinar.
- Política (longitud, igual al email, HIBP) → 422 con errores en `newPassword`.
- HIBP caído con `Hibp:FailOpen = false` → 422 `PASSWORD_TOO_WEAK` con un mensaje "intentá más tarde".
- `forgot-password` solo envía mail a cuentas confirmadas y no bloqueadas por admin; siempre 202.
- El reset exitoso levanta el lockout por intentos fallidos (no el bloqueo de admin) y revoca todas las sesiones.

## D-020 · MFA

- **Secretos en DB**: Identity guarda por defecto los recovery codes y la clave TOTP en texto plano en
  `AspNetUserTokens`. `AppUserStore` guarda los recovery codes como SHA-256 y la clave cifrada con Data
  Protection (`Auth.Identity.AuthenticatorKey`). Perder las claves de Data Protection obliga a reconfigurar MFA.
- **Challenge de login**: se usa `IDataProtector` con vencimiento propio (no `ITimeLimitedDataProtector`) para
  poder testear con `FakeTimeProvider`. Va atado al security stamp, al tipo de sesión pedido (`useCookies`) y
  es de uso único (`jti`). El `jti` se consume solo cuando el código es correcto: un error de tipeo no obliga a
  repetir la contraseña, y la fuerza bruta queda acotada por el lockout compartido (5 intentos) y el rate limit.
- **Anti-replay TOTP**: un código aceptado queda marcado 90 s por usuario (la ventana de Identity es ±2 pasos).
- `setup` solo funciona con MFA desactivado (409 si no); `disable` rota la clave y borra los recovery codes.
- En los endpoints de gestión, código incorrecto → 400 `MFA_INVALID` (el usuario sigue autenticado); en
  `login/mfa` → 401 `MFA_INVALID`.
