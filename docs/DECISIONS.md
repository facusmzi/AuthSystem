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
