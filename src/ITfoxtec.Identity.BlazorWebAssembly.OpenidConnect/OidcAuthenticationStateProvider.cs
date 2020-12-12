using Blazored.SessionStorage;
using ITfoxtec.Identity.Messages;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
{
    public class OidcAuthenticationStateProvider : AuthenticationStateProvider
    {
        private const string userSessionKey = "user_session";
        private readonly IServiceProvider serviceProvider;
        private readonly OpenidConnectPkceSettings openidClientPkceSettings;
        private readonly ISessionStorageService sessionStorage;

        public OidcAuthenticationStateProvider(IServiceProvider serviceProvider, OpenidConnectPkceSettings openidClientPkceSettings, ISessionStorageService sessionStorage)
        {
            this.serviceProvider = serviceProvider;
            this.openidClientPkceSettings = openidClientPkceSettings;
            this.sessionStorage = sessionStorage;
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var user = await GetClaimsPrincipalAsync();
            return await Task.FromResult(new AuthenticationState(user));
        }

        protected async Task<ClaimsPrincipal> GetClaimsPrincipalAsync()
        {
            var userSession = await GetUserSessionAsync();
            if (userSession != null)
            {
                return new ClaimsPrincipal(new ClaimsIdentity(userSession.Claims.Select(c => new Claim(c.Key, c.Value)), userSession.AuthenticationType, openidClientPkceSettings.NameClaimType, openidClientPkceSettings.RoleClaimType));
            }
            else
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

            var sessionClaims = new Dictionary<string, string>();
            foreach(var claim in claimsIdentity.Claims)
            {
                sessionClaims.Add(claim.Type, claim.Value);
            }

            var userSession = new OidcUserSession
            {
                ValidUntil = validUntil,
                Claims = sessionClaims,
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

        public async Task DeleteSessionAsync()
        {
            await sessionStorage.RemoveItemAsync(userSessionKey);

            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }
    }
}
