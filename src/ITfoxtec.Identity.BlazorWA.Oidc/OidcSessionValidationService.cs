using ITfoxtec.Identity.Discovery;
using ITfoxtec.Identity.Helpers;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
{
    public class OidcSessionValidationService : IAsyncDisposable
    {
        private readonly IServiceScopeFactory serviceScopeFactory;
        private readonly CancellationTokenSource validationCancellationTokenSource = new();
        private readonly Task validationMonitorTask;
        private readonly TimeSpan? validationInterval;
        private readonly object providersLock = new();
        private readonly HashSet<OidcAuthenticationStateProvider> providers = new();

        public OidcSessionValidationService(IServiceScopeFactory serviceScopeFactory, OpenidConnectPkceSettings openidClientPkceSettings)
        {
            this.serviceScopeFactory = serviceScopeFactory;

            if (openidClientPkceSettings.SessionValidationIntervalSeconds > 0)
            {
                validationInterval = TimeSpan.FromSeconds(openidClientPkceSettings.SessionValidationIntervalSeconds);
                validationMonitorTask = MonitorAccessTokenAsync(validationCancellationTokenSource.Token);
            }
        }

        internal void RegisterProvider(OidcAuthenticationStateProvider provider)
        {
            lock (providersLock)
            {
                providers.Add(provider);
            }
        }

        internal void UnregisterProvider(OidcAuthenticationStateProvider provider)
        {
            lock (providersLock)
            {
                providers.Remove(provider);
            }
        }

        private async Task MonitorAccessTokenAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(validationInterval.Value, cancellationToken);
                    await ValidateAccessTokenWithUserInfoAsync();
                }
                catch (TaskCanceledException)
                { }
                catch
                {
                    await HandleLogoutAsync(GetRegisteredProviders());
                }
            }
        }

        private async Task ValidateAccessTokenWithUserInfoAsync()
        {
            var registeredProviders = GetRegisteredProviders();
            if (registeredProviders.Count == 0)
            {
                return;
            }

            using var scope = serviceScopeFactory.CreateScope();

            var primaryProvider = registeredProviders[0];
            var userSession = await primaryProvider.GetUserSessionAsync(readInvalidSession: true);
            if (userSession == null || userSession.AccessToken.IsNullOrEmpty())
            {
                return;
            }

            try
            {
                var discoveryHandler = scope.ServiceProvider.GetService<OidcDiscoveryHandler>();
                var validationHelper = scope.ServiceProvider.GetService<OidcHelper>();
                discoveryHandler.SetDefaultOidcDiscoveryUri(userSession.OidcDiscoveryUri);
                await validationHelper.ValidateAccessTokenWithUserInfoEndpoint(userSession.AccessToken);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Access token validation: {ex.Message}");
                await HandleLogoutAsync(registeredProviders);
            }
        }

        private static async Task HandleLogoutAsync(IEnumerable<OidcAuthenticationStateProvider> providers)
        {
            foreach (var provider in providers)
            {
                try
                {
                    await provider.HandleLogoutAsync();
                }
                catch
                { }
            }
        }

        private List<OidcAuthenticationStateProvider> GetRegisteredProviders()
        {
            lock (providersLock)
            {
                return providers.ToList();
            }
        }

        public async ValueTask DisposeAsync()
        {
            validationCancellationTokenSource.Cancel();
            if (validationMonitorTask != null)
            {
                try
                {
                    await validationMonitorTask;
                }
                catch (TaskCanceledException)
                { }
                catch
                { }
            }
            validationCancellationTokenSource.Dispose();
        }
    }
}
