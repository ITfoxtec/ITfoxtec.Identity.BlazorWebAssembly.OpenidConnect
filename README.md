# ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect

> ## ITfoxtec changed to [FoxIDs](https://www.foxids.com)
> The company name ITfoxtec has changed to FoxIDs but the components will keep the ITfoxtec name as part of the component name for now.

A JavaScript free OpenID Connect PKCE library for Blazor WebAssembly.

* **Support .NET 9.0**
* **Support .NET 8.0**
* **Support .NET 7.0**
* **Support .NET 6.0**
* **Support .NET 5.0**

The library support login and logout with OpenID Connect (OIDC) using Proof Key for Code Exchange (PKCE) instead of a client secret.
The received ID token is validated by the component in the client using the OpenID Provider (OP) discovery document.  
The component automatically handle token / session update with use of refresh tokens if the offline_access scope is specified.

> Please see the [sample application](https://github.com/ITfoxtec/ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect/tree/master/samples) for implementation details.  
> The sample application is configured to authenticate with [foxids.com](https://foxids.com) using test user `test1@foxids.com` or `test2@foxids.com` and password `TestAccess!`  
> For more information about the European Identity Services FoxIDs, please see the [FoxIDs documentation](https://foxids.com/docs).

## Install
Install the ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect NuGet package via the Visual Studio package manger. 

Or install via PowerShell using the following command.

```powershell
Install-Package ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
```

Or via CLI.

```bash
dotnet add package ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
```

### Setup and configuration
Register the OpenidConnectPkce, the HttpClient and the IHttpClientFactory in the _Program.cs_ file.

```c#
private static void ConfigureServices(IServiceCollection services, WebAssemblyHostConfiguration configuration, IWebAssemblyHostEnvironment hostEnvironment)
{
    services.AddHttpClient("BlazorWebAssemblyOidcSample.API", client => client.BaseAddress = new Uri(hostEnvironment.BaseAddress))
        .AddHttpMessageHandler<AccessTokenMessageHandler>();

    services.AddTransient(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient("BlazorWebAssemblyOidcSample.API"));

    services.AddOpenidConnectPkce(settings =>
    {
        configuration.Bind("IdentitySettings", settings);
    });
}
```

Add _appsettings.json_ and possible _appsettings.Development.json_ configuration files under wwwroot with the _IdentitySettings_ configuration. The scope is added as a space separated list of values.

```json
{
  "IdentitySettings": {
    "Authority": "https://...some authority.../",
    "ClientId": "...client id...",
    "Scope": "...some scope..." 
  }
}
```

Add the library namespace `@using ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect` to __Imports.razor_.

### IdP configuration
Configuration the Blazor client as a OpenID Connect client on the IdP.

```
Response types: code
Enable PKCE: true
Login call back: ...base URL.../authentication/login_callback
Logout call back: ...base URL.../authentication/logout_callback
```

### API calls to another domain
The configuration can be expanded to support API calls to another domains then the base domain. The trusted _AuthorizedUris_ in the _IdentitySettings_ configuration is configured on the AccessTokenMessageHandler. 

```c#
private static void ConfigureServices(IServiceCollection services, WebAssemblyHostConfiguration configuration, IWebAssemblyHostEnvironment hostEnvironment)
{
    services.AddHttpClient("BlazorWebAssemblyOidcSample.API", client => client.BaseAddress = new Uri(hostEnvironment.BaseAddress))
        .AddHttpMessageHandler(sp =>
        {
            var handler = sp.GetService<AccessTokenMessageHandler>();
            configuration.Bind("IdentitySettings", handler);
            return handler;
        });

    services.AddTransient(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient("BlazorWebAssemblyOidcSample.API"));

    services.AddOpenidConnectPkce(settings =>
    {
        configuration.Bind("IdentitySettings", settings);
    });
}
```

Add trusted domains as _AuthorizedUris_ in the _IdentitySettings_ configuration. 

```json
{
  "IdentitySettings": {
    "Authority": "https://...some authority.../",
    "ClientId": "...client id...",
    "Scope": "...some scope...",
    "Resources": [ "...resource..." ],
    "AuthorizedUris": [ "...authorized api Uri..." ]
  }
}
```


### Add call back page
Add a _Authentication.razor_ call back page in the _Pages_ folder with the following content.

```c#
@page "/authentication/{action}"
@inherits AuthenticationPageBase
```

### Authorize views
Update the _App.razor_ to include _AuthorizeRouteView/NotAuthorized_ with the _OidcRedirectToLogin_ element. The _OidcRedirectToLogin_ start the login flow if the user do not have access.

```html
<Router AppAssembly="@typeof(Program).Assembly">
    <Found Context="routeData">
        <AuthorizeRouteView RouteData="@routeData" DefaultLayout="@typeof(MainLayout)">
            <NotAuthorized>
                <OidcRedirectToLogin />
            </NotAuthorized>
            <Authorizing>
                <h1>Authentication in progress</h1>
                <p>Only visible while authentication is in progress.</p>
            </Authorizing>
        </AuthorizeRouteView>
    </Found>
    <NotFound>
        <CascadingAuthenticationState>
            <LayoutView Layout="@typeof(MainLayout)">
                <h1>Sorry</h1>
                <p>Sorry, there's nothing at this address.</p>
            </LayoutView>
        </CascadingAuthenticationState>
    </NotFound>
</Router>
```

Thereby both the _Authorize_ attribute and AuthorizeView are supported.

### Login / logout menu
Possible add the _LoginDisplay.razor_ with a login / logout menu with the following content.

```c#
@inject OpenidConnectPkce oenidConnectPkce

<AuthorizeView>
    <Authorized>
        Hello, @context.User.Identity.Name!
        <button class="nav-link btn btn-link" @onclick="LogoutAsync">Logout</button>
    </Authorized>
    <NotAuthorized>
        <button class="nav-link btn btn-link" @onclick="LoginAsync">Login</button>
    </NotAuthorized>
</AuthorizeView>

@code{
    private async Task LoginAsync(MouseEventArgs args)
    {
        await oenidConnectPkce.LoginAsync();
    }

    private async Task LogoutAsync(MouseEventArgs args)
    {
        await oenidConnectPkce.LogoutAsync();
    }
}
```

The _LoginDisplay_ can be added to the _MainLayout.razor_ like this.

```c#
@inherits LayoutComponentBase

<div class="sidebar">
    <NavMenu />
</div>

<div class="main">
    <div class="top-row px-4">
        <LoginDisplay />
    </div>

    <div class="content px-4">
        @Body
    </div>
</div>

```

### Support
If you have questions please ask them on [Stack Overflow](https://stackoverflow.com/questions/tagged/itfoxtec-identity-blazor). Tag your questions with 'itfoxtec-identity-blazor' and I will answer as soon as possible.