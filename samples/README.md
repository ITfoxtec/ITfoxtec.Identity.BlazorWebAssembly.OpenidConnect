The Client, Server and Shared sample projects target .NET 11. Install the .NET 11 SDK to build and run them.

To run the sample set the BlazorWebAssemblyOidcSample.Server as startup project, or run the following commands from the repository root:

```powershell
dotnet restore ITfoxtec.Identity.BlazorWA.Oidc.sln
dotnet build ITfoxtec.Identity.BlazorWA.Oidc.sln -c Release --no-restore
dotnet run --project samples/BlazorWAOidcSample.Server --no-launch-profile -- --urls https://localhost:44315 --environment Development
```

Login with test user `test1@foxids.com` or `test2@foxids.com` and password `TestAccess!`

After upgrading the framework or dependencies, verify login and the OIDC callback, an authorised API call, token refresh after the access token expires, and logout. For cross-domain API testing, configure the API's CORS policy and include its base URI in `IdentitySettings:AuthorizedUris`.
