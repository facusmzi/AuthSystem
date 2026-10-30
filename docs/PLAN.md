# Plan: Servicio de Autenticación y Autorización (ASP.NET Core)

> Documento de especificación para implementar desde cero un servicio de auth profesional,
> inspirado en la capa de seguridad de [staroverlay/backend](https://github.com/staroverlay/backend)
> (TypeScript/Elysia), pero implementado de forma idiomática en .NET.
> **No es una traducción línea por línea**: se conserva el comportamiento y se corrigen sus debilidades.

> **Cambio respecto a la versión original:** la capa HTTP usa **controllers** (`[ApiController]`) en lugar de
> Minimal APIs. El resto del plan no cambia. Ver `docs/DECISIONS.md` (D-012) para las equivalencias y el resto
> de las decisiones tomadas durante la implementación.

---

## 0. Instrucciones para Claude Code

- Leé este documento completo antes de crear archivos.
- Implementá **por fases** (sección 15). Al terminar cada fase: `dotnet build` sin warnings y `dotnet test` en verde. No avances con tests rotos.
- Escribí los tests **junto con** cada feature, no al final.
- Nunca loguees contraseñas, tokens, códigos MFA, recovery codes ni claves.
- No commitees secretos. Usá `dotnet user-secrets` en desarrollo.
- Ante una decisión no cubierta acá, elegí la opción más segura y dejala anotada en `docs/DECISIONS.md`.
- Verificá la licencia de cada paquete NuGet antes de agregarlo (sección 3). Solo licencias permisivas (MIT, Apache 2.0, BSD).
- Preguntá antes de cambiar una decisión de este documento.

---

## 1. Decisiones tomadas

| Tema | Decisión |
|---|---|
| Framework | **.NET 10 (LTS)**. Ver nota abajo. |
| Base de identidad | **ASP.NET Core Identity** (`AddIdentityCore`), sin `MapIdentityApi` (sus bearer tokens son propietarios, no JWT) |
| Persistencia | Entity Framework Core + **SQLite** |
| Arquitectura | **Clean Architecture**: Domain / Application / Infrastructure / Api + tests |
| Estilo de API | **Controllers** (`[ApiController]`), filtros MVC, versión en ruta `/api/v1` |
| Clientes | **Ambos**: SPA web con **cookie HttpOnly** (sin tokens en JS) + apps nativas/servicios con **JWT Bearer + refresh token** |
| Autorización | **Roles + permisos granulares** con políticas dinámicas |
| Extras v1 | **MFA TOTP**, **reset de contraseña**, **auditoría de seguridad**, **chequeo de contraseñas filtradas (HIBP)** |
| Hash de contraseñas | **Argon2id** (m=64 MiB, t=3, p=4) reemplazando el `PasswordHasher` PBKDF2 de Identity |
| Firma JWT | **ES256** (ECDSA P-256) con `kid` y JWKS publicado, soporte de rotación de claves |

> **Nota sobre la versión:** el pedido original era .NET 9, pero .NET 9 (STS) deja de tener soporte el
> **10 de noviembre de 2026**. Para un proyecto nuevo y "profesional" se usa **.NET 10 LTS**.
> Si igual se quiere .NET 9, solo cambian `global.json`, `TargetFramework` y las versiones de paquetes.

---

## 2. Análisis del sistema original (referencia)

### 2.1 Cómo funciona
- **Access token**: JWT HS256 (`jose`), claims `sub`, `sessionId`, `type:"access"`, 10 min.
- **Middleware** (`src/middlewares/auth.ts`): valida Bearer → firma/tipo → busca la **sesión en DB** (no revocada, no vencida) → usuario → perfil. Esto da **revocación inmediata**.
- **`requireVerified`**: además exige email verificado (403).
- **Registro**: email normalizado a minúsculas, regex de contraseña (8+, mayúscula, minúscula, dígito), whitelist beta opcional en Redis, argon2id, código de verificación de 6 dígitos por email.
- **Login**: argon2 verify → 401 genérico; si email no verificado → 403 `EMAIL_NOT_VERIFIED`; crea sesión.
- **Refresh**: JWT con secreto separado, 30 días, guardado como SHA-256 en `sessions`. **Rotación** en cada uso manteniendo el mismo `sessionId` y ventana deslizante. **Período de gracia de 3 min** (Redis) que devuelve el mismo par ante refrescos concurrentes.
- **Logout**: soft-revoke (`revokedAt`) de la sesión actual o de todas. Listado y revocación de sesiones por id (404/403).
- **Roles/permisos**: **no existen**. Autorización por identidad + email verificado + propiedad del recurso.
- **Transversal**: rate limit por IP+ruta (Redis), CORS restringido con credentials, headers de seguridad, errores `{error, code}`, 422 en validación.

### 2.2 Archivos de referencia
| Funcionalidad | Archivo |
|---|---|
| Middleware auth | `src/middlewares/auth.ts` |
| Rate limit | `src/middlewares/rate-limit.ts` |
| JWT / rotación | `src/lib/jwt.ts` |
| Lógica de auth | `src/services/auth.service.ts` |
| Sesiones | `src/services/sessions.service.ts`, `src/routes/sessions.routes.ts` |
| Endpoints | `src/routes/auth.routes.ts` |
| Esquema | `src/database/schema.ts`, `drizzle/0000_init.sql` |
| Errores | `src/lib/errors.ts`, `src/lib/request-helpers.ts`, `src/index.ts` |
| Config | `src/lib/env.ts`, `.env.example` |

### 2.3 Bugs y debilidades a NO replicar
1. `change-password` no revoca sesiones aunque lo promete.
2. `verify-email` sin rate limit ni límite de intentos → fuerza bruta del código de 6 dígitos.
3. Código con `Math.random()` y guardado en texto plano.
4. Expiración inconsistente (1 h en código, 15 min en mail, cooldown roto ≈46 min).
5. `DELETE /sessions/:id` siempre dice "Current session revoked".
6. Login sin tiempo constante (enumeración de emails); register/verify/resend revelan si el email existe.
7. Secreto interno comparado con `!==` (no constante).
8. Rate limit "falla abierto".
9. Sin detección de reutilización de refresh token.
10. JWT sin `iss`/`aud`/`jti`.
11. Bypass de código `000000` atado solo a `NODE_ENV`.
12. Tokens devueltos en JSON a una SPA → expuestos a XSS si se guardan en `localStorage`.

---

## 3. Paquetes NuGet

Usar **Central Package Management** (`Directory.Packages.props`).

| Paquete | Uso | Licencia |
|---|---|---|
| `Microsoft.AspNetCore.Identity.EntityFrameworkCore` | Identity + EF | MIT |
| `Microsoft.EntityFrameworkCore.Sqlite`, `.Design`, `.Tools` | DB | MIT |
| `Microsoft.AspNetCore.Authentication.JwtBearer` | JWT | MIT |
| `Microsoft.AspNetCore.OpenApi` + `Scalar.AspNetCore` | Docs (solo dev) | MIT |
| `FluentValidation.DependencyInjectionExtensions` | Validación | Apache 2.0 |
| `Konscious.Security.Cryptography.Argon2` | Argon2id | MIT |
| `Microsoft.Extensions.Http.Resilience` | Timeout/retry HIBP | MIT |
| `MailKit` | SMTP | MIT |
| Tests: `xunit`, `Microsoft.AspNetCore.Mvc.Testing`, `Microsoft.Extensions.TimeProvider.Testing`, `NSubstitute`, `Shouldly` | Tests | Permisivas |

> **No usar FluentAssertions v8+**: desde 2025 es licencia comercial (Xceed). Usar **Shouldly** o `Assert`.
> **No usar Duende IdentityServer/BFF**: licencia comercial. Todo lo de acá es gratis.

---

## 4. Estructura de la solución

```
auth/
├─ Auth.sln
├─ global.json                    (pin SDK 10.x)
├─ Directory.Build.props          (Nullable, ImplicitUsings, TreatWarningsAsErrors, AnalysisLevel latest)
├─ Directory.Packages.props       (versiones centralizadas)
├─ .editorconfig
├─ .gitignore                     (incluye *.db, keys/, appsettings.*.local.json)
├─ docs/
│  ├─ DECISIONS.md
│  └─ API.md
├─ src/
│  ├─ Auth.Domain/                (sin dependencias)
│  │  ├─ Sessions/   Session.cs, SessionKind.cs, LoginMethod.cs, RevocationReason.cs
│  │  ├─ Audit/      SecurityAuditEvent.cs, AuditEventType.cs
│  │  ├─ Authorization/ Permissions.cs (constantes), SystemRoles.cs
│  │  └─ Common/     IClock? (usar TimeProvider), DomainException.cs
│  ├─ Auth.Application/           (depende de Domain)
│  │  ├─ Abstractions/ IAuthService, ISessionService, ITokenService, IMfaService,
│  │  │                IPasswordService, IAuditLogger, IEmailSender, IPasswordBreachChecker,
│  │  │                IPermissionService, ICurrentUser, IClientInfo, IUserAdminService, IRoleAdminService
│  │  ├─ Common/       Result<T>, Error, ErrorCodes, PagedResult<T>
│  │  ├─ Features/
│  │  │  ├─ Auth/      DTOs + Validators (Register, Login, LoginMfa, Refresh, ForgotPassword, ResetPassword, ConfirmEmail)
│  │  │  ├─ Account/   DTOs + Validators (Me, ChangePassword, Mfa*)
│  │  │  ├─ Sessions/  DTOs
│  │  │  └─ Admin/     DTOs + Validators (Users, Roles, Audit)
│  │  └─ DependencyInjection.cs
│  ├─ Auth.Infrastructure/        (depende de Application)
│  │  ├─ Identity/     ApplicationUser, ApplicationRole, RolePermission, Argon2PasswordHasher,
│  │  │                LongLivedEmailConfirmationTokenProvider, BreachedPasswordValidator, MaxLengthPasswordValidator
│  │  ├─ Persistence/  AppDbContext, Configurations/, Migrations/, UtcDateTimeConverter, DbSeeder
│  │  ├─ Tokens/       EcdsaSigningKeyProvider, JwtTokenService, RefreshTokenGenerator, MfaChallengeProtector
│  │  ├─ Services/     AuthService, SessionService, MfaService, PasswordService, PermissionService,
│  │  │                AuditLogger, UserAdminService, RoleAdminService
│  │  ├─ Security/     HibpPasswordBreachChecker, HashingConcurrencyLimiter
│  │  ├─ Email/        SmtpEmailSender, LoggingEmailSender, EmailTemplates
│  │  ├─ Background/   SessionCleanupService, AuditRetentionService
│  │  └─ DependencyInjection.cs
│  └─ Auth.Api/                   (depende de Application + Infrastructure)
│     ├─ Program.cs
│     ├─ appsettings.json, appsettings.Development.json
│     ├─ Controllers/  AuthController, AccountController, MfaController, AdminUsersController,
│     │                AdminRolesController, AdminAuditController, WellKnownController
│     ├─ Authentication/ AuthSchemes.cs, SmartSchemeSelector, JwtBearerEventsHandler, CookieEventsHandler
│     ├─ Authorization/  PermissionRequirement, PermissionHandler, PermissionPolicyProvider, HasPermissionAttribute
│     ├─ Filters/      ValidationFilter (action filter global), AntiforgeryForCookiesFilter
│     ├─ Middleware/   SecurityHeadersMiddleware
│     ├─ Errors/       GlobalExceptionHandler, ResultExtensions (Result → IActionResult/ProblemDetails)
│     ├─ Services/     CurrentUser, ClientInfo (IP/UA)
│     └─ Options/      JwtOptions, SessionOptions, CookieAuthOptions, CorsOptions, RateLimitOptions,
│                      PasswordPolicyOptions, HibpOptions, EmailOptions, SeedOptions, FrontendOptions
└─ tests/
   ├─ Auth.UnitTests/
   ├─ Auth.IntegrationTests/      (WebApplicationFactory + SQLite in-memory)
   └─ Auth.ArchitectureTests/     (opcional: reglas de dependencias entre capas)
```

**Reglas de dependencias**: Domain no depende de nada. Application no referencia EF Core ni ASP.NET.
Infrastructure implementa interfaces de Application. Api solo compone y expone.

---

## 5. Modelo de datos

Todas las fechas en **UTC** como `DateTime` con converter (SQLite no ordena bien `DateTimeOffset`).
Guids como TEXT. SQLite en **WAL** y `busy_timeout` configurado.

### 5.1 `ApplicationUser : IdentityUser<Guid>` (Infrastructure)
Campos de Identity (Email, NormalizedEmail, EmailConfirmed, PasswordHash, SecurityStamp,
TwoFactorEnabled, LockoutEnd, AccessFailedCount, …) más:
- `CreatedAt`, `UpdatedAt`
- `LastLoginAt?`
- `PasswordChangedAt?`
- Índice único en `NormalizedEmail` (`RequireUniqueEmail = true`). `UserName = Email`.

### 5.2 `ApplicationRole : IdentityRole<Guid>`
- `Description?`, `IsSystem` (no se puede borrar/renombrar: `Admin`, `User`).

### 5.3 `RolePermission`
- PK compuesta (`RoleId`, `Permission` string). FK a role con cascade.

### 5.4 `Session` (Domain)
| Campo | Notas |
|---|---|
| `Id` Guid | va en claim `sid` |
| `UserId` Guid | FK cascade |
| `Kind` | `Cookie` \| `Bearer` |
| `RefreshTokenHash?` | SHA-256 hex, **único**; null en sesiones cookie |
| `PreviousRefreshTokenHash?` | para detectar reutilización |
| `RefreshRotatedAt?` | |
| `LoginMethod` | `Password`, `PasswordMfa`, `RecoveryCode` |
| `IpAddress?`, `UserAgent?` | UA truncado a 512 |
| `CreatedAt`, `LastSeenAt` | |
| `ExpiresAt` | ventana deslizante (30 días, como el original) |
| `AbsoluteExpiresAt` | tope duro (90 días) — mejora |
| `RevokedAt?`, `RevokedReason?` | `Logout`, `LogoutAll`, `PasswordChanged`, `PasswordReset`, `MfaChanged`, `RefreshReuse`, `Admin`, `UserLocked` |

Índices: `UserId`, `RefreshTokenHash` (único), `PreviousRefreshTokenHash`, `ExpiresAt`.

### 5.5 `SecurityAuditEvent` (Domain)
- `Id` (long autoincrement), `OccurredAt`, `Type` (enum como string), `UserId?`, `ActorUserId?` (admin que actuó),
  `SessionId?`, `Email?` (normalizado, para fallos sin usuario), `IpAddress?`, `UserAgent?`, `Success`, `Details?` (JSON, **sin secretos**).
- Índices: `(UserId, OccurredAt)`, `(Type, OccurredAt)`.

### 5.6 `BetaWhitelistEntry` (opcional, feature flag)
- `NormalizedEmail` PK, `AddedAt`, `ConsumedAt?`.

### 5.7 Relaciones
`User 1─N Session`, `User N─N Role` (Identity `UserRoles`), `Role 1─N RolePermission`,
`User 1─N SecurityAuditEvent` (sin FK dura: los eventos sobreviven al borrado del usuario).

---

## 6. Autenticación

### 6.1 Esquemas
- `AddIdentityCore<ApplicationUser>().AddRoles<ApplicationRole>().AddEntityFrameworkStores<AppDbContext>().AddSignInManager().AddDefaultTokenProviders()`.
- Esquema **policy "Smart"** como default (`AddPolicyScheme` + `ForwardDefaultSelector`):
  si hay header `Authorization: Bearer` → `JwtBearer`; si no → `Cookie`.
- Nunca se aceptan ambos a la vez para la misma request.

### 6.2 JWT Bearer (apps nativas / servicios)
**Emisión** (`JsonWebTokenHandler`):
- Algoritmo **ES256**, header `kid` y `typ: at+jwt`.
- Claims: `sub` (userId), `sid` (sessionId), `jti`, `iat`, `nbf`, `exp`, `iss`, `aud`, `amr` (`pwd` / `mfa`), `email_verified`.
- Roles **no** van en el token para autorización (se resuelven en servidor, ver 7). Se puede incluir `role` solo como info para UI.
- Duración: **10 minutos** (`Jwt:AccessTokenMinutes`).

**Claves**:
- Clave privada EC P-256 en PEM, ruta en config (`Jwt:SigningKeys[]` con `kid`, `path`, `active`). En dev se genera sola si no existe.
- Varias claves de validación permitidas → rotación sin cortar sesiones.
- `GET /.well-known/jwks.json` publica solo las claves públicas.

**Validación** (`AddJwtBearer`):
- `ValidateIssuer/Audience/Lifetime/IssuerSigningKey = true`, `ValidAlgorithms = [ES256]`, `ValidTypes = ["at+jwt"]`.
- `ClockSkew = 30s`, `MapInboundClaims = false`, `NameClaimType = "sub"`.
- `OnTokenValidated`: `ISessionValidator.ValidateAsync(sid, userId)` → sesión activa, no vencida, usuario existe, no bloqueado. Si falla → `context.Fail(...)`.
- `OnChallenge`: responde ProblemDetails 401 con código (`AUTH_HEADER_MISSING`, `TOKEN_INVALID`, `TOKEN_EXPIRED`, `SESSION_REVOKED`). `HandleResponse()`.
- `OnForbidden`: ProblemDetails 403.

### 6.3 Cookie (SPA web, patrón BFF-like)
- La cookie **es** la sesión: contiene `sub` + `sid` (ticket protegido con Data Protection). No hay refresh token en el navegador.
- Nombre `__Host-auth`, `HttpOnly`, `Secure = Always`, `SameSite = Strict`, `Path=/`, sin `Domain`.
- `ExpireTimeSpan` = sesión deslizante (30 días), `SlidingExpiration = true`; respetar `AbsoluteExpiresAt`.
- Eventos:
  - `OnValidatePrincipal`: mismo `ISessionValidator`; si falla → `RejectPrincipal()` + `SignOutAsync`. Actualiza `LastSeenAt` como máximo cada 5 min.
  - `OnRedirectToLogin` → 401 ProblemDetails (API, sin redirects). `OnRedirectToAccessDenied` → 403.
- **CSRF**: `AddAntiforgery` con header `X-XSRF-TOKEN`. `GET /api/v1/auth/antiforgery` devuelve/setea el token.
  Filtro `AntiforgeryForCookiesFilter`: en métodos no seguros (POST/PUT/PATCH/DELETE), si la request se autenticó por **cookie**, valida antiforgery. Bearer no lo necesita.
  También se exige antiforgery en `login?useCookies=true` (login CSRF).
- Requisito de despliegue: la SPA debe servirse **same-site** con la API (mismo dominio registrable o detrás de un reverse proxy/YARP). Documentarlo en `docs/API.md`.

### 6.4 Data Protection
- `PersistKeysToFileSystem(keysPath)` con `SetApplicationName("Auth")`. En producción, proteger las claves (`ProtectKeysWithDpapi` en Windows o certificado).
- La usan: cookies, tokens de Identity (confirmación/reset), challenge MFA.

### 6.5 Validación de sesión (cache)
- `ISessionValidator` consulta DB y cachea el resultado positivo en `IMemoryCache` por **30 s** (clave `session:{sid}`).
- **Toda revocación invalida la entrada de cache** → la revocación sigue siendo prácticamente inmediata.

---

## 7. Autorización

### 7.1 Políticas base
- `FallbackPolicy` = autenticado **y** `email_verified`. Todo endpoint nuevo queda protegido por defecto.
- Endpoints públicos: `[AllowAnonymous]` explícito.
- Política `Authenticated` (sin exigir verificación) para logout y `/account/me` (por si en el futuro hay logins sin verificar).

### 7.2 Permisos
- Constantes en `Auth.Domain/Authorization/Permissions.cs`:
  - `users.read`, `users.manage`, `roles.read`, `roles.manage`, `roles.assign`,
  - `sessions.read.any`, `sessions.revoke.any`, `audit.read`.
- Roles del sistema (seed): `Admin` (todos los permisos), `User` (ninguno especial; acceso a su propia cuenta).
- `PermissionPolicyProvider : IAuthorizationPolicyProvider` → políticas con nombre `perm:{permiso}` generadas on-demand.
- `PermissionHandler` usa `IPermissionService.GetPermissionsAsync(userId)`:
  une permisos de todos los roles del usuario; cache `IMemoryCache` 5 min, **invalidado** al cambiar roles del usuario o permisos de un rol.
- Atributo de acción/controller: `[HasPermission(Permissions.UsersRead)]`.

### 7.3 Propiedad de recursos
- `ICurrentUser.UserId` / `SessionId`. Todas las consultas de "mi cuenta" filtran por `UserId`.
- `DELETE /account/sessions/{id}`: 404 si no existe **o** no es del usuario (no revelar existencia ajena — mejora sobre el 403 del original).

### 7.4 Primer administrador
- `Seed:AdminEmail` en config: al arrancar, si existe ese usuario y está confirmado, se le asigna `Admin`.
- Alternativa: comando `dotnet run --project src/Auth.Api -- seed-admin --email x`. No hay contraseñas de admin en config.

---

## 8. Contraseñas

### 8.1 Hashing
- `Argon2PasswordHasher : IPasswordHasher<ApplicationUser>` con Konscious:
  - Argon2id, `MemorySize = 65536` KiB, `Iterations = 3`, `DegreeOfParallelism = 4`, salt 16 bytes (`RandomNumberGenerator`), hash 32 bytes.
  - Formato **PHC**: `$argon2id$v=19$m=65536,t=3,p=4$<salt b64>$<hash b64>` (compatible con hashes del sistema original).
  - Comparación con `CryptographicOperations.FixedTimeEquals`.
  - Devuelve `SuccessRehashNeeded` si los parámetros guardados difieren de los actuales.
- `HashingConcurrencyLimiter` (SemaphoreSlim, p.ej. 4) para que muchos logins simultáneos no agoten la memoria (64 MiB por hash).
- **Tiempo constante en login**: si el usuario no existe, verificar contra un hash dummy precomputado.

### 8.2 Política (NIST SP 800-63B)
- Mínimo **12** caracteres, máximo **128** (`MaxLengthPasswordValidator`).
- **Sin** reglas de composición (mayúscula/número/símbolo): se desactivan en `IdentityOptions.Password`.
- Rechazar contraseña igual al email.
- **`BreachedPasswordValidator`** (HIBP, ver 8.3).
- Mensajes de validación claros (422).

### 8.3 Contraseñas filtradas (Have I Been Pwned)
- SHA-1 de la contraseña → `GET https://api.pwnedpasswords.com/range/{5 primeros hex}` con header `Add-Padding: true` (k-anonymity: la contraseña nunca sale del servidor).
- Comparar sufijos; si aparece con conteo ≥ `Hibp:MinBreachCount` (1) → rechazar con código `PASSWORD_BREACHED`.
- `HttpClient` tipado + `AddStandardResilienceHandler` (timeout total 3 s).
- Si HIBP no responde: **fail-open** configurable (`Hibp:FailOpen = true`) con log warning + evento de auditoría.
- Se aplica en: registro, cambio de contraseña, reset.

### 8.4 Bloqueo de cuenta (Identity Lockout)
- `MaxFailedAccessAttempts = 5`, `DefaultLockoutTimeSpan = 15 min`, `AllowedForNewUsers = true`.
- Login con `SignInManager.CheckPasswordSignInAsync(user, pwd, lockoutOnFailure: true)`.
- Fallos de MFA también cuentan para lockout (`AccessFailedAsync`).

---

## 9. Flujos

### 9.1 Registro — `POST /api/v1/auth/register`
1. Validar `{ email, password }`. Normalizar email.
2. Si `Features:BetaWhitelist` activo y el email no está → **igual** responder 202 (no revelar) y no crear nada. (Variante aceptable: 403 explícito como el original — decidir y anotar.)
3. Si el email ya existe → **no** devolver 409: responder **202** y enviar al dueño real un mail "alguien intentó registrarse con tu email".
4. Crear usuario (rol `User`), enviar mail de confirmación con link `{Frontend:BaseUrl}/confirm-email?userId=..&token=..`.
5. Respuesta siempre `202 { message: "If the email is valid, you'll receive a confirmation link." }`.
6. Auditoría: `Registered` / `RegistrationAttemptExistingEmail`.

> Cambio respecto al original: link con token de Identity en vez de código de 6 dígitos. Elimina la fuerza bruta (bug 2-4).

### 9.2 Confirmar email — `POST /api/v1/auth/confirm-email` `{ userId, token }`
- `UserManager.ConfirmEmailAsync`. Token válido **24 h** (`LongLivedEmailConfirmationTokenProvider`). Respuesta 200 o 400 `INVALID_TOKEN` genérico.
- Rate limit.

### 9.3 Reenviar confirmación — `POST /api/v1/auth/resend-confirmation` `{ email }`
- Siempre 202. Cooldown real de 60 s por usuario (guardado en cache/DB), más rate limit por IP.

### 9.4 Login — `POST /api/v1/auth/login?useCookies=false` `{ email, password }`
1. Buscar usuario; si no existe → hash dummy → 401 `INVALID_CREDENTIALS`.
2. `CheckPasswordSignInAsync(lockoutOnFailure: true)`:
   - Bloqueado → 401 `INVALID_CREDENTIALS` (genérico) + auditoría `LoginLockedOut`.
   - Inválido → 401 genérico + auditoría `LoginFailed`.
3. Contraseña correcta pero email no confirmado → 403 `EMAIL_NOT_CONFIRMED` (solo se revela con contraseña correcta, como el original).
4. Si `TwoFactorEnabled` → 200 `{ requiresMfa: true, mfaToken }` (ver 9.6). No se crea sesión todavía.
5. Si no → crear sesión:
   - `useCookies=true`: `Kind=Cookie`, `SignInAsync(Cookie)`, respuesta 200 `{ user }`. Requiere antiforgery.
   - `useCookies=false`: `Kind=Bearer`, respuesta 200 `TokenResponse`.
6. Si el hasher pidió rehash → actualizar hash. Actualizar `LastLoginAt`. Auditoría `LoginSucceeded`.

### 9.5 Refresh — `POST /api/v1/auth/refresh` `{ refreshToken }` (solo Bearer)
- Refresh token **opaco**: 32 bytes aleatorios en base64url. En DB solo `SHA-256`.
- Algoritmo:
  1. `hash = SHA256(token)`.
  2. **Gracia**: si `IMemoryCache["refresh-grace:{hash}"]` existe → devolver ese mismo `TokenResponse` (refrescos concurrentes, como el original; 3 min).
  3. Buscar sesión por `RefreshTokenHash == hash`, activa, no vencida (`ExpiresAt` y `AbsoluteExpiresAt`).
  4. Si no hay, pero existe una sesión con `PreviousRefreshTokenHash == hash` **fuera** de la gracia → **reutilización detectada**: revocar sesión (`RefreshReuse`), auditoría crítica, 401.
  5. Generar nuevo par. **Update condicional atómico**: `ExecuteUpdateAsync(... WHERE Id = s.Id AND RefreshTokenHash = hash)` seteando nuevo hash, `PreviousRefreshTokenHash = hash`, `RefreshRotatedAt`, `ExpiresAt` deslizante (sin pasar `AbsoluteExpiresAt`), IP/UA. Si afecta 0 filas → otra request ganó la carrera → reintentar paso 2.
  6. Guardar en cache de gracia y devolver.
- Cualquier error → 401 `REFRESH_INVALID` genérico.
- Para sesiones cookie no hay refresh: la cookie se desliza sola.

### 9.6 MFA en login — `POST /api/v1/auth/login/mfa?useCookies=` `{ mfaToken, code? , recoveryCode? }`
- `mfaToken`: `ITimeLimitedDataProtector` (propósito `mfa-challenge`), contiene `userId`, `securityStamp`, `jti`, `useCookies`, vence en **5 min**.
- Validar que el `securityStamp` siga igual y que el `jti` no se haya usado (cache) → uso único.
- `code`: `VerifyTwoFactorTokenAsync(user, AuthenticatorTokenProvider, code)`. Rechazar reutilización del mismo código (cache `totp-used:{userId}:{code}` 90 s).
- `recoveryCode`: `RedeemTwoFactorRecoveryCodeAsync` (uso único). Auditoría `RecoveryCodeUsed`; avisar por mail.
- Fallo → `AccessFailedAsync` (cuenta para lockout), 401 `MFA_INVALID`. Rate limit estricto.
- Éxito → crear sesión con `LoginMethod = PasswordMfa | RecoveryCode`, `amr = mfa`.

### 9.7 Gestión de MFA (autenticado)
| Endpoint | Acción |
|---|---|
| `GET /account/mfa` | `{ enabled, recoveryCodesLeft }` |
| `POST /account/mfa/setup` | `ResetAuthenticatorKeyAsync` → `{ sharedKey, otpauthUri }` (`otpauth://totp/{Issuer}:{email}?secret=..&issuer=..&digits=6`). El cliente genera el QR. |
| `POST /account/mfa/enable` `{ code }` | Verifica código → `SetTwoFactorEnabledAsync(true)` → devuelve **10 recovery codes** (una sola vez). Revoca las demás sesiones. |
| `POST /account/mfa/disable` `{ password, code }` | Requiere contraseña **y** código. Revoca las demás sesiones. |
| `POST /account/mfa/recovery-codes` `{ code }` | Regenera códigos. |
- Todos auditados. Mail de aviso al activar/desactivar.

### 9.8 Olvidé mi contraseña — `POST /api/v1/auth/forgot-password` `{ email }`
- Siempre 202. Si el usuario existe y está confirmado → `GeneratePasswordResetTokenAsync` (vida **1 h**) → mail con link `{Frontend}/reset-password?email=..&token=..`.
- Rate limit + cooldown por usuario.

### 9.9 Reset — `POST /api/v1/auth/reset-password` `{ email, token, newPassword }`
- `ResetPasswordAsync` (aplica validadores, incluido HIBP). Error genérico `INVALID_TOKEN`.
- Éxito → **revocar todas las sesiones** (`PasswordReset`), resetear lockout, mail de aviso, auditoría.

### 9.10 Cambio de contraseña — `POST /api/v1/account/change-password` `{ currentPassword, newPassword }`
- `ChangePasswordAsync`. Éxito → **revocar todas las demás sesiones** (la actual sigue), `PasswordChangedAt`, mail de aviso, auditoría.
- (Corrige el bug 1 del original.)

### 9.11 Logout
- `POST /auth/logout` → revoca sesión actual (`Logout`); en cookie también `SignOutAsync`. 204.
- `POST /auth/logout-all` → revoca todas (`LogoutAll`), incluida la actual. 204.

### 9.12 Sesiones propias
- `GET /account/sessions` → activas, ordenadas por `CreatedAt desc`, con `current: bool`, `kind`, `loginMethod`, IP, UA, fechas.
- `DELETE /account/sessions/{id}` → revoca; respuesta indica `{ wasCurrent }` correctamente (corrige bug 5).

---

## 10. Endpoints (resumen)

Prefijo `/api/v1`.

| Método | Ruta | Acceso | Rate limit |
|---|---|---|---|
| POST | `/auth/register` | anónimo | `strict` |
| POST | `/auth/confirm-email` | anónimo | `strict` |
| POST | `/auth/resend-confirmation` | anónimo | `strict` |
| GET | `/auth/antiforgery` | anónimo | — |
| POST | `/auth/login` | anónimo (+antiforgery si cookies) | `login` |
| POST | `/auth/login/mfa` | anónimo | `mfa` |
| POST | `/auth/refresh` | anónimo | `refresh` |
| POST | `/auth/forgot-password` | anónimo | `strict` |
| POST | `/auth/reset-password` | anónimo | `strict` |
| POST | `/auth/logout` | `Authenticated` | — |
| POST | `/auth/logout-all` | `Authenticated` | — |
| GET | `/account/me` | `Authenticated` | — |
| POST | `/account/change-password` | verificado | `strict` |
| GET/POST | `/account/mfa/*` | verificado | `mfa` en verificaciones |
| GET | `/account/sessions` | verificado | — |
| DELETE | `/account/sessions/{id}` | verificado | — |
| GET | `/admin/users?search&page&pageSize` | `users.read` | — |
| GET | `/admin/users/{id}` | `users.read` | — |
| POST | `/admin/users/{id}/lock` / `unlock` | `users.manage` | — |
| PUT | `/admin/users/{id}/roles` | `roles.assign` | — |
| GET | `/admin/users/{id}/sessions` | `sessions.read.any` | — |
| DELETE | `/admin/sessions/{id}` | `sessions.revoke.any` | — |
| GET/POST/PUT/DELETE | `/admin/roles[/{id}]` (con permisos) | `roles.read` / `roles.manage` | — |
| GET | `/admin/permissions` | `roles.read` | — |
| GET | `/admin/audit?userId&type&from&to&page` | `audit.read` | — |
| GET | `/.well-known/jwks.json` | anónimo | — |
| GET | `/health/live`, `/health/ready` | anónimo | — |

`/account/me` devuelve `{ id, email, emailConfirmed, mfaEnabled, roles[], permissions[], createdAt }`.

Reglas admin: un admin no puede quitarse a sí mismo el rol `Admin` si es el último; bloquear usuario revoca sus sesiones (`UserLocked`); roles `IsSystem` no se borran.

---

## 11. DTOs principales (Application)

```
RegisterRequest(string Email, string Password)
ConfirmEmailRequest(Guid UserId, string Token)
EmailRequest(string Email)                         // resend / forgot
LoginRequest(string Email, string Password)
LoginMfaRequest(string MfaToken, string? Code, string? RecoveryCode)   // exactamente uno
RefreshRequest(string RefreshToken)
ResetPasswordRequest(string Email, string Token, string NewPassword)
ChangePasswordRequest(string CurrentPassword, string NewPassword)
MfaCodeRequest(string Code)
DisableMfaRequest(string Password, string Code)

TokenResponse(string AccessToken, DateTime AccessTokenExpiresAt, string RefreshToken, DateTime RefreshTokenExpiresAt, string TokenType = "Bearer")
LoginResponse(bool RequiresMfa, string? MfaToken, TokenResponse? Tokens, MeResponse? User)
MeResponse(Guid Id, string Email, bool EmailConfirmed, bool MfaEnabled, IReadOnlyList<string> Roles, IReadOnlyList<string> Permissions, DateTime CreatedAt)
SessionDto(Guid Id, string Kind, string LoginMethod, string? IpAddress, string? UserAgent, DateTime CreatedAt, DateTime LastSeenAt, DateTime ExpiresAt, bool Current)
MfaSetupResponse(string SharedKey, string OtpAuthUri)
RecoveryCodesResponse(IReadOnlyList<string> Codes)
AdminUserDto, RoleDto(Guid Id, string Name, string? Description, bool IsSystem, IReadOnlyList<string> Permissions)
AuditEventDto, PagedResult<T>(IReadOnlyList<T> Items, int Page, int PageSize, int Total)
```

Validación con FluentValidation; un `ValidationFilter` global (action filter de MVC) ejecuta el validador de cada argumento de la acción.

---

## 12. Errores

- Patrón **`Result<T>` / `Error(code, message, status)`** en Application para errores esperados (no excepciones para control de flujo).
- `ResultExtensions.ToActionResult()` → ProblemDetails (**RFC 9457**): `type`, `title`, `status`, `detail`, extensiones `code` y `traceId`.
- `GlobalExceptionHandler : IExceptionHandler` para excepciones inesperadas → 500 genérico; detalle solo en Development.
- `AddProblemDetails()` para que 404/405/415 también sean ProblemDetails.
- Validación → **422** `ValidationProblemDetails` con `errors` por campo (como el original). Errores de binding (body ausente/JSON inválido) → 400 vía `InvalidModelStateResponseFactory`.
- Códigos (`ErrorCodes`): `VALIDATION_FAILED`, `INVALID_CREDENTIALS`, `EMAIL_NOT_CONFIRMED`, `MFA_REQUIRED`, `MFA_INVALID`, `TOKEN_INVALID`, `TOKEN_EXPIRED`, `SESSION_REVOKED`, `REFRESH_INVALID`, `INVALID_TOKEN`, `PASSWORD_BREACHED`, `PASSWORD_TOO_WEAK`, `FORBIDDEN`, `NOT_FOUND`, `RATE_LIMITED`, `ANTIFORGERY_INVALID`, `CONFLICT`, `INTERNAL_ERROR`.

---

## 13. Middleware, CORS, rate limiting y headers

Orden en `Program.cs`:
```
UseForwardedHeaders (solo KnownProxies/KnownNetworks de config)
UseExceptionHandler
UseHsts (prod) + UseHttpsRedirection
SecurityHeadersMiddleware
UseCors("Frontend")
UseRateLimiter
UseAuthentication
UseAuthorization
UseAntiforgery
MapControllers
```

- **Headers**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`,
  `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` (relajar solo para la UI de Scalar en dev),
  `Permissions-Policy` restrictiva, `Cache-Control: no-store` en respuestas de `/auth/*` y `/account/*`. **No** usar `X-XSS-Protection`.
- **CORS** (`Cors:AllowedOrigins` exactos): `AllowCredentials`, headers `Content-Type, Authorization, X-XSRF-TOKEN`, métodos GET/POST/PUT/PATCH/DELETE. Nunca `*` con credentials.
- **Rate limiting** (`Microsoft.AspNetCore.RateLimiting`, partición por IP real; nunca falla abierto porque es en memoria):
  - `strict`: 5/min · `login`: 10/min · `mfa`: 5/min · `refresh`: 10/min · global: 100/min por IP.
  - Rechazo: 429 ProblemDetails `RATE_LIMITED` + header `Retry-After`.
- **IP real**: `ForwardedHeaders` solo si `Network:TrustProxy = true` y con proxies conocidos (corrige la confianza ciega en `X-Forwarded-For`).

---

## 14. Configuración

`appsettings.json` (sin secretos):
```json
{
  "ConnectionStrings": { "Default": "Data Source=auth.db" },
  "Jwt": {
    "Issuer": "https://auth.local",
    "Audience": "auth-api",
    "AccessTokenMinutes": 10,
    "SigningKeys": [ { "Kid": "dev-1", "Path": "keys/jwt-dev-1.pem", "Active": true } ]
  },
  "Sessions": { "SlidingDays": 30, "AbsoluteDays": 90, "RefreshGraceMinutes": 3, "ValidationCacheSeconds": 30 },
  "PasswordPolicy": { "MinLength": 12, "MaxLength": 128 },
  "Lockout": { "MaxFailedAttempts": 5, "LockoutMinutes": 15 },
  "Hibp": { "Enabled": true, "FailOpen": true, "TimeoutSeconds": 3 },
  "Mfa": { "Issuer": "Auth", "ChallengeMinutes": 5, "RecoveryCodes": 10 },
  "Tokens": { "EmailConfirmationHours": 24, "PasswordResetMinutes": 60 },
  "Cors": { "AllowedOrigins": [ "http://localhost:5173" ] },
  "Frontend": { "BaseUrl": "http://localhost:5173" },
  "Network": { "TrustProxy": false, "KnownProxies": [] },
  "Features": { "BetaWhitelist": false },
  "Email": { "Provider": "Logging", "From": "noreply@example.com", "Smtp": { "Host": "", "Port": 587, "UseStartTls": true } },
  "DataProtection": { "KeysPath": "keys/dp" },
  "Audit": { "RetentionDays": 180 },
  "Seed": { "AdminEmail": "" }
}
```
- Secretos (`Email:Smtp:User/Password`, rutas de claves de prod) por `user-secrets` o variables de entorno.
- Todas las opciones con `AddOptions<T>().BindConfiguration(...).ValidateDataAnnotations().ValidateOnStart()`.
- `TimeProvider` inyectado en todos los servicios (testeable con `FakeTimeProvider`).

---

## 15. Plan de implementación por fases

Cada fase termina con build sin warnings + tests en verde + commit.

1. **Esqueleto**: solución, 4 proyectos + 2 de tests, `global.json`, `Directory.*.props`, `.editorconfig`, `.gitignore`, `Program.cs` mínimo con `/health`, ProblemDetails, headers, CORS. Test de humo.
2. **Persistencia + Identity**: entidades, `AppDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, Guid>`, configuraciones, converter UTC, WAL, migración inicial, seed de roles/permisos. `Argon2PasswordHasher` + validadores de contraseña (sin HIBP aún).
3. **Registro y confirmación de email**: endpoints 9.1–9.3, `IEmailSender` (logging), rate limits, auditoría básica.
4. **Sesiones + JWT**: claves ES256, JWKS, `JwtTokenService`, `SessionService`, `ISessionValidator`, login Bearer, refresh con gracia + detección de reuso, logout, logout-all, `/account/me`, `/account/sessions`.
5. **Cookies + CSRF**: esquema smart, cookie auth, `OnValidatePrincipal`, antiforgery, login con `useCookies`.
6. **Autorización**: permission policy provider/handler, `IPermissionService` con cache, endpoints admin (users, roles, sessions, audit), seed del primer admin.
7. **Contraseñas**: change-password, forgot/reset, HIBP con resiliencia, lockout.
8. **MFA**: setup/enable/disable/recovery codes, challenge de login, anti-replay.
9. **Auditoría completa + background services**: todos los eventos, limpieza de sesiones vencidas y retención de auditoría.
10. **Pulido**: OpenAPI + Scalar (dev), `docs/API.md`, `docs/DECISIONS.md`, revisión de seguridad con la checklist (sección 17).

---

## 16. Tests

### 16.1 Unitarios (`Auth.UnitTests`)
- `Argon2PasswordHasher`: hash/verify, contraseña incorrecta, formato PHC, `SuccessRehashNeeded` al cambiar parámetros, verifica un hash PHC generado por la librería `argon2` de Node.
- Validadores de contraseña: longitud mín/máx, igual al email, sin reglas de composición.
- `HibpPasswordBreachChecker`: sufijo encontrado/no encontrado, padding, timeout → fail-open/fail-closed (HttpMessageHandler falso).
- `JwtTokenService`: claims, `typ`, `kid`, `iss/aud`, expiración con `FakeTimeProvider`.
- `RefreshTokenGenerator`: longitud/entropía, hash determinista.
- `MfaChallengeProtector`: expira, rechaza stamp cambiado, uso único.
- `PermissionService`: unión de permisos de varios roles, invalidación de cache.
- Validators de FluentValidation.

### 16.2 Integración (`Auth.IntegrationTests`, `WebApplicationFactory` + SQLite in-memory con conexión abierta compartida, `FakeTimeProvider`, email sender en memoria)
**Registro/confirmación**: 202 siempre; email existente no revela (202 + mail al dueño); contraseña débil/filtrada → 422; confirmar con token válido/ inválido/vencido; resend cooldown.
**Login**: éxito Bearer; éxito cookie (cookie `__Host-`, HttpOnly, Secure, SameSite=Strict); credenciales inválidas 401; usuario inexistente 401 (mismo código); email sin confirmar 403; lockout tras 5 fallos y desbloqueo tras 15 min.
**JWT**: sin header 401; header mal formado; token vencido; firma alterada; `alg` distinto (HS256/none) rechazado; `iss`/`aud` incorrectos; refresh token usado como access; sesión revocada → 401 inmediato.
**Refresh**: rotación; token viejo inválido después de la gracia; dentro de la gracia devuelve el mismo par; refrescos concurrentes (Task.WhenAll) sin romper la sesión; reuso fuera de la gracia revoca la sesión; vencimiento deslizante y absoluto.
**Cookies/CSRF**: POST autenticado por cookie sin antiforgery → 400/403; con antiforgery → OK; Bearer no requiere antiforgery; logout invalida la cookie.
**Logout/sesiones**: logout, logout-all, listado con `current`, revocar sesión ajena → 404, `wasCurrent` correcto.
**Contraseñas**: change-password revoca las demás sesiones y conserva la actual; reset revoca todas; forgot siempre 202; token de reset de un solo uso.
**MFA**: setup → enable con código válido (calculado en el test con la clave compartida) → login pide MFA → `login/mfa` OK; código inválido cuenta para lockout; mismo código reutilizado rechazado; recovery code de un solo uso; `mfaToken` vencido o reutilizado; disable requiere contraseña + código.
**Autorización**: usuario sin permiso → 403; admin → 200; cambio de rol aplica sin re-login (tras invalidar cache); no se puede quitar el último admin; bloquear usuario revoca sus sesiones; fallback policy protege un endpoint de prueba sin atributos.
**Transversal**: 429 con `Retry-After`; headers de seguridad presentes; CORS preflight con origen permitido/no permitido; formato ProblemDetails con `code` y `traceId`; `jwks.json` no expone clave privada.
**Auditoría**: cada flujo genera su evento; ningún evento contiene contraseñas/tokens.

### 16.3 Arquitectura (opcional, `NetArchTest.Rules`)
- Domain no referencia otros proyectos; Application no referencia EF Core ni ASP.NET Core.

---

## 17. Checklist de seguridad final

- [ ] Ningún secreto en el repo; `.gitignore` cubre `*.db`, `keys/`.
- [ ] Logs sin contraseñas, tokens, códigos, recovery codes ni hashes.
- [ ] Respuestas genéricas en register/forgot/resend/login (sin enumeración).
- [ ] Login en tiempo constante (hash dummy).
- [ ] Todas las comparaciones de secretos con `FixedTimeEquals`.
- [ ] Refresh tokens y códigos solo hasheados en DB.
- [ ] Revocación de sesiones en: logout, logout-all, cambio/reset de contraseña, cambios de MFA, bloqueo, reuso de refresh, admin.
- [ ] Cookies `__Host-`, HttpOnly, Secure, SameSite=Strict + antiforgery.
- [ ] JWT: ES256 solo, `typ`, `iss`, `aud`, `ClockSkew` 30 s.
- [ ] Rate limits en todos los endpoints anónimos.
- [ ] HTTPS + HSTS en producción; Data Protection keys protegidas.
- [ ] Fallback policy activa; cada endpoint anónimo marcado explícitamente.
- [ ] Dependencias con licencias permisivas; `dotnet list package --vulnerable` limpio.

> Estado de la checklist tras la implementación: ver el final de `docs/DECISIONS.md`.

---

## 18. Fuera de alcance (v1)

- Login con OAuth externo (Twitch/Kick/YouTube/Google). Dejar `LoginMethod` extensible para agregarlo como `External`.
- Passkeys/WebAuthn (en .NET 10 Identity ya trae soporte: buen candidato para v2).
- Autenticación de servicios con API keys / secreto interno y tokens de widget del original.
- Multi-instancia (cache distribuida). Con SQLite se asume una sola instancia; para escalar, mover cache a Redis y DB a PostgreSQL.
