---
id: dotnet_service
version: 1
covers: []
standards: ["cwe", "asvs5", "api-top10-2023"]
max_tokens: 1500
---
## Runtime and framework model
A C# or F# service on .NET: ASP.NET Core (controllers, Minimal APIs, Razor Pages, Blazor Server,
SignalR, gRPC), Worker Services, Azure Functions, or legacy ASP.NET/WCF on .NET Framework. The
middleware pipeline in `Program.cs` defines request processing order; attributes and conventions
drive routing, binding, and authorization.

## Trust and interface layer
- Entry points: controller actions, `MapGet`/`MapPost` endpoints, Razor page handlers, SignalR hub
  methods, gRPC services, queue and blob triggers, `IHostedService` consumers.
- Model binding fills parameters from route, query, form, headers, and JSON body; complex types
  bind recursively.
- `app.UseAuthentication()` and `app.UseAuthorization()` must run between `UseRouting` and the
  endpoints; `[Authorize]`, `[AllowAnonymous]`, policies, and fallback policies govern access.

## Idiomatic security mechanisms
- `AuthorizationOptions.FallbackPolicy` requiring authenticated users; resource-based
  `IAuthorizationService.AuthorizeAsync(user, resource, policy)`.
- EF Core LINQ and `FromSqlInterpolated` (parameterizes), Dapper parameters.
- Razor encodes by default; antiforgery tokens (`[ValidateAntiForgeryToken]`, automatic for Razor
  Pages forms).
- `System.Text.Json` without polymorphic type handling; Data Protection API for cookies and tokens.
- `JwtBearer` with `TokenValidationParameters` validating issuer, audience, lifetime, and key.

## Stack-specific pitfalls
- `FromSqlRaw`/`ExecuteSqlRaw` with interpolated strings; `SqlCommand` text concatenation.
- `@Html.Raw`, `MarkupString` in Blazor, `HtmlString` around user content.
- `BinaryFormatter`, `LosFormatter`, `ObjectStateFormatter`, `NetDataContractSerializer`,
  Newtonsoft `TypeNameHandling` other than `None`; ViewState without MAC on .NET Framework.
- `XmlDocument`/`XmlTextReader` on .NET Framework before 4.5.2 resolving external entities.
- Middleware order mistakes (authorization before routing, endpoints mapped before auth),
  `[AllowAnonymous]` on a controller overriding action-level `[Authorize]`.
- Overposting: binding request bodies directly into EF entities.
- `ServerCertificateCustomValidationCallback` returning true; `HttpClient` fetching user URLs.
- Developer exception page or detailed errors enabled outside Development.
- `Process.Start` with `UseShellExecute = true` or concatenated `Arguments`.

## Build and deployment facts to check
- `ASPNETCORE_ENVIRONMENT` and per-environment `appsettings.*.json` values.
- Target framework (.NET Framework vs modern .NET) since parser and serializer defaults differ.
- NuGet package versions from the resolved graph and `packages.lock.json` use.
- Kestrel bind addresses, forwarded-headers configuration (`KnownProxies`), HTTPS redirection and
  HSTS.
- Connection strings and secrets sources (user secrets, Key Vault, environment).
