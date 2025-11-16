using Blazored.SessionStorage;
using ITfoxtec.Identity.Discovery;
using ITfoxtec.Identity.Helpers;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Logging;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;

namespace ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddOpenidConnectPkce(this IServiceCollection services, Action<OpenidConnectPkceSettings> settings)
        {
            IdentityModelEventSource.ShowPII = true;

            services.AddBlazoredSessionStorage();

            var openIDClientPkceSettings = new OpenidConnectPkceSettings();
            settings(openIDClientPkceSettings);
            services.AddSingleton(openIDClientPkceSettings);

            services.AddScoped<OpenidConnectPkce>();
            services.AddSingleton(sp => new OidcDiscoveryHandler(sp.GetService<IHttpClientFactory>()));
            services.AddScoped(sp => new OidcHelper(sp.GetService<IHttpClientFactory>(), sp.GetService<OidcDiscoveryHandler>()));

            services.AddScoped<OidcAuthenticationStateProvider>();
            services.AddScoped<AuthenticationStateProvider>(sp => sp.GetRequiredService<OidcAuthenticationStateProvider>());
            services.AddScoped<AccessTokenMessageHandler>();

            services.AddOptions();
            services.AddAuthorizationCore();

            // Added to resolve error: Newtonsoft.Json.JsonSerializationException: Unable to find a default constructor to use for type System.IdentityModel.Tokens.Jwt.JwtPayload. Path 'sub', line 1, position 7.
            // https://github.com/mono/linker/issues/870
            _ = new JwtHeader();
            _ = new JwtPayload();

            return services;
        }
    }
}
