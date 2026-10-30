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
