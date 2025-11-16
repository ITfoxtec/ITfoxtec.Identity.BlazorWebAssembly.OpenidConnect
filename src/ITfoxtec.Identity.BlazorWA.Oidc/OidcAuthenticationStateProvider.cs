using Blazored.SessionStorage;
using ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect.Models;
using ITfoxtec.Identity.Messages;
using ITfoxtec.Identity.Helpers;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
{
    public class OidcAuthenticationStateProvider : AuthenticationStateProvider, IAsyncDisposable
    {
        private const string userSessionKey = "user_session";
        private readonly IServiceProvider serviceProvider;
        private readonly OpenidConnectPkceSettings openidClientPkceSettings;
        private readonly ISessionStorageService sessionStorage;
        private readonly OidcHelper oidcHelper;
        private readonly CancellationTokenSource validationCancellationTokenSource = new();
        private readonly Task validationMonitorTask;
        private readonly TimeSpan? validationInterval;
        private bool raisingLogoutEvent;

        public event EventHandler LogoutDetected;

        public OidcAuthenticationStateProvider(IServiceProvider serviceProvider, OpenidConnectPkceSettings openidClientPkceSettings, ISessionStorageService sessionStorage, OidcHelper oidcHelper)
        {
            this.serviceProvider = serviceProvider;
            this.openidClientPkceSettings = openidClientPkceSettings;
            this.sessionStorage = sessionStorage;
            this.oidcHelper = oidcHelper;

            if (openidClientPkceSettings.SessionValidationIntervalSeconds > 0)
            {
                validationInterval = TimeSpan.FromSeconds(openidClientPkceSettings.SessionValidationIntervalSeconds);
                validationMonitorTask = MonitorAccessTokenAsync(validationCancellationTokenSource.Token);
            }
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var user = await GetClaimsPrincipalAsync();
            return await Task.FromResult(new AuthenticationState(user));
        }

        protected async Task<ClaimsPrincipal> GetClaimsPrincipalAsync()
        {
            try
            {
                var userSession = await GetUserSessionAsync();
                if (userSession != null)
                {
                    return new ClaimsPrincipal(new ClaimsIdentity(userSession.Claims.Select(c => new Claim(c.Type, c.Value, c.ValueType, c.Issuer, c.OriginalIssuer)), userSession.AuthenticationType, openidClientPkceSettings.NameClaimType, openidClientPkceSettings.RoleClaimType));
                }
                else
                {
                    return new ClaimsPrincipal(new ClaimsIdentity());
                }
            }
            catch (TokenUnavailableException)
            {
                return new ClaimsPrincipal(new ClaimsIdentity());
            }
        }

        public async Task<string> GetIdToken(bool readInvalidSession = false)
        {
            var userSession = await GetUserSessionAsync(readInvalidSession);
            return userSession?.IdToken;
        }

        public async Task<string> GetAccessToken(bool readInvalidSession = false)
        {
            var userSession = await GetUserSessionAsync(readInvalidSession);
            return userSession?.AccessToken;
        }

        protected async Task<OidcUserSession> GetUserSessionAsync(bool readInvalidSession = false)
        {
            var userSession = await sessionStorage.GetItemAsync<OidcUserSession>(userSessionKey);
            if (userSession != null)
            {
                try
                {
                    userSession = await serviceProvider.GetService<OpenidConnectPkce>().HandleRefreshTokenAsync(userSession);

                    if (userSession.ValidUntil >= DateTimeOffset.UtcNow)
                    {
                        return userSession;
                    }
                    else
                    {
                        await DeleteSessionAsync();

                        if (readInvalidSession)
                        {
                            return userSession;
                        }
                    }
                }
                catch (TokenUnavailableException)
                {
                    await DeleteSessionAsync(false);
                    if (readInvalidSession)
                    {
                        return null;
                    }
                    else
                    {
                        throw;
                    }
                }
            }

            return null;
        }

        public Task<OidcUserSession> CreateSessionAsync(DateTimeOffset validUntil, ClaimsPrincipal claimsPrincipal, TokenResponse tokenResponse, string sessionState, OpenidConnectPkceState openidClientPkceState)
        {
            return CreateUpdateSessionAsync(validUntil, claimsPrincipal, tokenResponse, sessionState, openidClientPkceState.OidcDiscoveryUri, openidClientPkceState.ClientId);
        }

        public Task<OidcUserSession> UpdateSessionAsync(DateTimeOffset validUntil, ClaimsPrincipal claimsPrincipal, TokenResponse tokenResponse, string sessionState, OidcUserSession userSession)
        {
            return CreateUpdateSessionAsync(validUntil, claimsPrincipal, tokenResponse, sessionState, userSession.OidcDiscoveryUri, userSession.ClientId);
        }

        private async Task<OidcUserSession> CreateUpdateSessionAsync(DateTimeOffset validUntil, ClaimsPrincipal claimsPrincipal, TokenResponse tokenResponse, string sessionState, string oidcDiscoveryUri, string clientId)
        {
            var claimsIdentity = claimsPrincipal.Identities.First();
            var claimsList = claimsIdentity.Claims.Select(c => new ClaimValue { Type = c.Type, Value = c.Value, ValueType = c.ValueType, Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer }).ToList();

            var userSession = new OidcUserSession
            {
                ValidUntil = validUntil,
                Claims = claimsList,
                AuthenticationType = claimsIdentity.AuthenticationType,
                IdToken = tokenResponse.IdToken,
                AccessToken = tokenResponse.AccessToken,
                RefreshToken = tokenResponse.RefreshToken,
                SessionState = sessionState,
                OidcDiscoveryUri = oidcDiscoveryUri,
                ClientId = clientId
            };
            await sessionStorage.SetItemAsync(userSessionKey, userSession);

            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
            return userSession;
        }

        public async Task DeleteSessionAsync(bool notify = true)
        {
            await sessionStorage.RemoveItemAsync(userSessionKey);

            if(notify)
            {
                NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
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
                {
                }
                catch
                {
                    await HandleLogoutAsync();
                }
            }
        }

        private async Task ValidateAccessTokenWithUserInfoAsync()
        {
            var userSession = await sessionStorage.GetItemAsync<OidcUserSession>(userSessionKey);
            if (userSession == null)
            {
                return;
            }

            if (userSession.AccessToken.IsNullOrEmpty())
            {
                return;
            }

            try
            {
                await oidcHelper.ValidateAccessTokenWithUserInfoEndpoint(userSession.AccessToken);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Access token validation: {ex.Message}");
                await HandleLogoutAsync();
            }
        }

        private async Task HandleLogoutAsync()
        {
            await DeleteSessionAsync();
            RaiseLogoutDetected();
        }

        private void RaiseLogoutDetected()
        {
            if (raisingLogoutEvent)
            {
                return;
            }

            try
            {
                raisingLogoutEvent = true;
                LogoutDetected?.Invoke(this, EventArgs.Empty);
            }
            finally
            {
                raisingLogoutEvent = false;
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
                {
                }
                catch
                {
                }
            }
            validationCancellationTokenSource.Dispose();
        }
    }
}
