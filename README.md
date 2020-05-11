# ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
A JavaScript free OpenID Connect PKCE library for Blazor WebAssembly.

The library support login and logout with OpenID Connect (OIDC) using Proof Key for Code Exchange (PKCE) instead of a client secret.

> Please see the [sample application](https://github.com/ITfoxtec/ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect/tree/master/samples) for implementation details.

## Install
Install the ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect NuGet package via the Visual Studio package manger. 

Or install via powershell using the following command.

```powershell
Install-Package ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
```

Or via CLI.

```bash
dotnet add package ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
```

### Setup and configuration
Register the OpenidConnectPkce and the HttpClient in the _Program.cs_ file. The library requires the HttpClient.

```c#
private static void ConfigureServices(IServiceCollection services, WebAssemblyHostConfiguration configuration, IWebAssemblyHostEnvironment hostEnvironment)
{
    services.AddTransient(sp => new HttpClient { BaseAddress = new Uri(hostEnvironment.BaseAddress) });

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
    "Scope": "...some authority..." 
  }
}
```

Add the library namespace `@using ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect` to __Imports.razor_.

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
