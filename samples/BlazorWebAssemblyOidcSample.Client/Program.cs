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
        public static async Task Main(string[] args)
        {
            var builder = WebAssemblyHostBuilder.CreateDefault(args);
            builder.RootComponents.Add<App>("app");
            ConfigureServices(builder.Services, builder.Configuration, builder.HostEnvironment);

            await builder.Build().RunAsync();
        }

        private static void ConfigureServices(IServiceCollection services, WebAssemblyHostConfiguration configuration, IWebAssemblyHostEnvironment hostEnvironment)
        {
            services.AddTransient(sp => new HttpClient { BaseAddress = new Uri(hostEnvironment.BaseAddress) });

            services.AddOpenidConnectPkce(settings =>
            {
                configuration.Bind("IdentitySettings", settings);
            });
        }
    }
}
