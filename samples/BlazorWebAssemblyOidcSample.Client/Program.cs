using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect;

namespace BlazorWebAssemblyOidcSample.Client
{
    public class Program
    {
        const string httpClientLogicalName = "BlazorWebAssemblyOidcSample.API";

        public static async Task Main(string[] args)
        {
            var builder = WebAssemblyHostBuilder.CreateDefault(args);
            builder.RootComponents.Add<App>("app");
            ConfigureServices(builder.Services, builder.Configuration, builder.HostEnvironment);

            await builder.Build().RunAsync();
        }

        private static void ConfigureServices(IServiceCollection services, WebAssemblyHostConfiguration configuration, IWebAssemblyHostEnvironment hostEnvironment)
        {
            services.AddHttpClient(httpClientLogicalName, client => client.BaseAddress = new Uri(hostEnvironment.BaseAddress))
                .AddHttpMessageHandler<AccessTokenMessageHandler>();
                //.AddHttpMessageHandler(sp =>
                //{
                //    var handler = sp.GetService<AccessTokenMessageHandler>();
                //    configuration.Bind("IdentitySettings", handler);
                //    return handler;
                //});

            services.AddTransient(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient(httpClientLogicalName));

            services.AddOpenidConnectPkce(settings =>
            {
                configuration.Bind("IdentitySettings", settings);
            });
        }
    }
}
