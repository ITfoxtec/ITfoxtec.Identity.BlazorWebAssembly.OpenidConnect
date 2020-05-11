using Blazored.SessionStorage;
using Microsoft.AspNetCore.Components.Authorization;
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
        private readonly OpenidConnectPkceSettings openidClientPkceSettings;
        private readonly ISessionStorageService sessionStorage;

        public OidcAuthenticationStateProvider(OpenidConnectPkceSettings openidClientPkceSettings, ISessionStorageService sessionStorage)
        {
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

        public async Task<string> GetIdToken()
        {
            var userSession = await GetUserSessionAsync();
            return userSession?.IdToken;
        }
        public async Task<string> GetAccessToken()
        {
            var userSession = await GetUserSessionAsync();
            return userSession?.AccessToken;
        }

        protected async Task<OidcUserSession> GetUserSessionAsync()
        {
            var userSession = await sessionStorage.GetItemAsync<OidcUserSession>(userSessionKey);
            if (userSession != null)
            {
                if (userSession.ValidUntil >= DateTimeOffset.UtcNow)
                {
                    return userSession;
                }
                else
                {
                    await DeleteSessionAsync();
                }
            }

            return null;
        }

        public async Task CreateSessionAsync(DateTimeOffset validUntil, ClaimsPrincipal claimsPrincipal, string idToken, string accessToken, string sessionState)
        {
            var claimsIdentity = claimsPrincipal.Identities.First();
            var userSession = new OidcUserSession
            {
                ValidUntil = validUntil,
                Claims = claimsIdentity.Claims.Select(c => new KeyValuePair<string, string>(c.Type, c.Value)),
                AuthenticationType = claimsIdentity.AuthenticationType,
                IdToken = idToken,
                AccessToken = accessToken,
                SessionState = sessionState
            };
            await sessionStorage.SetItemAsync(userSessionKey, userSession);

            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }

        public async Task DeleteSessionAsync()
        {
            await sessionStorage.RemoveItemAsync(userSessionKey);
        }
    }
}
