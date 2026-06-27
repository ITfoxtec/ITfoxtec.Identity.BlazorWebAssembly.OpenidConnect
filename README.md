# ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect

> ## ITfoxtec changed to [FoxIDs](https://www.foxids.com)
> The company name ITfoxtec has changed to FoxIDs but the components will keep the ITfoxtec name as part of the component name for now.

A JavaScript free OpenID Connect PKCE library for Blazor WebAssembly.

[NuGet package](https://www.nuget.org/packages/ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect)

```powershell
dotnet add package ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
```

* **Support .NET 10.0**
* **Support .NET 9.0**
* **Support .NET 8.0**
* **Support .NET 7.0**
* **Support .NET 6.0**
* **Support .NET 5.0**

The library supports login and logout with OpenID Connect (OIDC) using Proof Key for Code Exchange (PKCE) instead of a client secret.
The received ID token is validated by the component in the client using the OpenID Provider (OP) discovery document.  
The component automatically handles token and session updates with refresh tokens if the offline_access scope is specified.

Please see the [sample application](https://github.com/ITfoxtec/ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect/tree/master/samples).

### More information
You can read more on [ITfoxtec Identity Blazor WebAssembly OpenID Connect Component Page](https://www.foxids.com/components/identityblazorwaoidc).

### Support
If you have questions please ask them on [Stack Overflow](https://stackoverflow.com/questions/tagged/itfoxtec-identity-blazor). Tag your questions with 'itfoxtec-identity-blazor'.

> You can use the [JWT tool](https://www.foxids.com/tools/jwt) to decode tokens and create self-signed certificates with the [certificate tool](https://www.foxids.com/tools/certificate).
