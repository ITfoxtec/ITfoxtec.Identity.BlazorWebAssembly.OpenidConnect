using Blazored.SessionStorage;
using ITfoxtec.Identity.Discovery;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Net.Http;

namespace ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddOpenidConnectPkce(this IServiceCollection services, Action<OpenidConnectPkceSettings> settings)
        {
            services.AddBlazoredSessionStorage();

            var openIDClientPkceSettings = new OpenidConnectPkceSettings();
            settings(openIDClientPkceSettings);
            services.AddSingleton(openIDClientPkceSettings);

            services.AddScoped<OpenidConnectPkce>();
            services.AddSingleton(sp => new OidcDiscoveryHandler(sp.GetService<HttpClient>()));

            services.AddScoped<AuthenticationStateProvider, OidcAuthenticationStateProvider>();

            services.AddOptions();
            services.AddAuthorizationCore();

            return services;
        }
    }
}
