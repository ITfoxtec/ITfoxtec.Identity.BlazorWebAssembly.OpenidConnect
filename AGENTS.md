# Repository Guidelines

## Project Structure & Module Organization
The solution is anchored by `ITfoxtec.Identity.BlazorWA.Oidc.sln`. Core library code lives in `src/ITfoxtec.Identity.BlazorWA.Oidc`, which exposes the `OpenidConnectPkce` entry point, `AccessTokenMessageHandler`, and Razor helpers such as `OidcRedirectToLogin.razor`. Shared DTOs and helpers sit under `Models/` and `Extensions/`. The `samples/BlazorWAOidcSample.{Client,Server,Shared}` projects provide the canonical integration testbed wired to FoxIDs; use them to validate sign-in, sign-out, and API calls. Static assets and configuration JSON reside under each project’s `wwwroot` folder.

## Build, Test, and Development Commands
Use `dotnet restore ITfoxtec.Identity.BlazorWA.Oidc.sln` before local work. `dotnet build ITfoxtec.Identity.BlazorWA.Oidc.sln -c Release` validates the multi-target library and sample apps. Run the interactive sample via `dotnet run --project samples/BlazorWAOidcSample.Server` and a second terminal for `samples/BlazorWAOidcSample.Client` to complete the OIDC loop. When you add unit tests, place them in a `*.Tests` project and execute `dotnet test ITfoxtec.Identity.BlazorWA.Oidc.sln`. `dotnet pack src/ITfoxtec.Identity.BlazorWA.Oidc/ITfoxtec.Identity.BlazorWA.Oidc.csproj` produces a NuGet package aligned with release builds.

## Coding Style & Naming Conventions
Follow .NET conventions: four-space indentation, braces on new lines, `PascalCase` types/methods, `camelCase` locals, and `_camelCase` private fields. Keep async APIs suffixed `Async` and prefer expression-bodied members only for trivial getters. Configuration objects mirror the `IdentitySettings` section, so stick with strongly typed options instead of raw dictionaries. Run `dotnet format` before submitting and ensure public APIs remain XML-documented.

## Testing Guidelines
Automated tests are currently light; lean on the sample apps for manual verification of login/logout, token refresh, and cross-domain API calls. When adding tests, use xUnit, name files `<Feature>Tests.cs`, and isolate network dependencies through mocks so they run in CI. Aim for meaningful coverage on `OpenidConnectPkce` flows and token handling, and document new manual test steps in `samples/README.md`.

## Security & Configuration Tips
Do not commit real `IdentitySettings` secrets; rely on user secrets or environment variables. Keep trusted URIs inside `AuthorizedUris`, validate callback URLs, and ensure new dependencies do not reintroduce JavaScript-based token handling. Review sample configurations whenever you change scopes or FoxIDs endpoints.
