using Blazored.SessionStorage;
using ITfoxtec.Identity.Discovery;
using ITfoxtec.Identity.Messages;
using ITfoxtec.Identity.Tokens;
using ITfoxtec.Identity.Util;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
{
    public class OpenidConnectPkce
    {
        protected readonly OpenidConnectPkceSettings globalOpenidClientPkceSettings;
        protected readonly HttpClient httpClient;
        protected readonly NavigationManager navigationManager;
        protected readonly ISessionStorageService sessionStorage;
        protected readonly OidcDiscoveryHandler oidcDiscoveryHandler;
        private readonly AuthenticationStateProvider authenticationStateProvider;

        public OpenidConnectPkce(OpenidConnectPkceSettings globalOpenidClientPkceSettings, HttpClient httpClient, NavigationManager navigationManager, ISessionStorageService sessionStorage, OidcDiscoveryHandler oidcDiscoveryHandler, AuthenticationStateProvider authenticationStateProvider)
        {
            this.globalOpenidClientPkceSettings = globalOpenidClientPkceSettings;
            this.httpClient = httpClient;
            this.navigationManager = navigationManager;
            this.sessionStorage = sessionStorage;
            this.oidcDiscoveryHandler = oidcDiscoveryHandler;
            this.authenticationStateProvider = authenticationStateProvider;
        }

        public async Task LoginAsync(OpenidConnectPkceSettings openidClientPkceSettings = null)
        {
            try
            {
                openidClientPkceSettings = openidClientPkceSettings ?? globalOpenidClientPkceSettings;

                var nonce = RandomGenerator.GenerateNonce();
                var codeVerifier = RandomGenerator.Generate(64);

                ValidateResponseMode(openidClientPkceSettings.ResponseMode);
                var loginCallBackUri = new Uri(new Uri(navigationManager.BaseUri), openidClientPkceSettings.LoginCallBackPath).OriginalString;
                var state = await SaveStateAsync(openidClientPkceSettings.OidcDiscoveryUri, openidClientPkceSettings.ClientId, loginCallBackUri, navigationManager.Uri, codeVerifier: codeVerifier, nonce: nonce);

                var authenticationRequest = new AuthenticationRequest
                {
                    ClientId = openidClientPkceSettings.ClientId,
                    ResponseMode = openidClientPkceSettings.ResponseMode,
                    ResponseType = openidClientPkceSettings.ResponseType,
                    RedirectUri = loginCallBackUri,
                    Scope = openidClientPkceSettings.AllScope.ToSpaceList(),
                    Nonce = nonce,
                    State = state
                };
                var codeChallengeRequest = new CodeChallengeSecret
                {
                    CodeChallenge = await codeVerifier.Sha256HashBase64urlEncoded(),
                    CodeChallengeMethod = IdentityConstants.CodeChallengeMethods.S256,
                };

                var nameValueCollection = authenticationRequest.ToDictionary().AddToDictionary(codeChallengeRequest);
                var oidcDiscovery = await GetOidcDiscoveryAsync(openidClientPkceSettings.OidcDiscoveryUri);
                var authorizationUrl = QueryHelpers.AddQueryString(oidcDiscovery.AuthorizationEndpoint, nameValueCollection);
                navigationManager.NavigateTo(authorizationUrl);

            }
            catch (Exception ex)
            {
                throw new SecurityException($"Failed to login, Authority '{openidClientPkceSettings.Authority}'.", ex);
            }
        }

        private void ValidateResponseMode(string responseMode)
        {
            if(responseMode != IdentityConstants.ResponseModes.Fragment && responseMode != IdentityConstants.ResponseModes.Query)
            {
                throw new NotSupportedException($"Response mode {responseMode} not supported. Only fragment and query is supported.");
            }
        }

        public async Task LoginCallBackAsync(string responseUrl)
        {
            try
            {
                var responseSplit = responseUrl.Split(responseUrl.Contains('#') ? '#' : '?');
                if (responseUrl.Count() <= 1)
                {
                    throw new SecurityException("Invalid response url.");
                }                
                var response = QueryHelpers.ParseQuery(responseSplit[1]).ToDictionary();

                var authenticationResponse = response.ToObject<AuthenticationResponse>();
                authenticationResponse.Validate();
                if (authenticationResponse.State.IsNullOrEmpty()) throw new ArgumentNullException(nameof(authenticationResponse.State), authenticationResponse.GetTypeName());

                var openidClientPkceState = await GetState(authenticationResponse.State);
                if (openidClientPkceState == null)
                {
                    throw new SecurityException($"State '{authenticationResponse.State}' do not exist.");
                }

                (var expiresIn, var idTokenPrincipal, var accessToken) = await AcquireTokensAsync(openidClientPkceState, authenticationResponse.Code);

                var sessionResponse = response.ToObject<SessionResponse>();
                sessionResponse.Validate();

                var validUntil = DateTimeOffset.UtcNow.AddSeconds(expiresIn).AddMinutes(globalOpenidClientPkceSettings.TokensExpiresBefore);
                await (authenticationStateProvider as OidcAuthenticationStateProvider).LoginAsync(validUntil, idTokenPrincipal, accessToken, sessionResponse.SessionState);
                navigationManager.NavigateTo(openidClientPkceState.RedirectUri);
            }
            catch (Exception ex)
            {
                throw new SecurityException($"Failed to handle login call back, response url '{responseUrl}'.", ex);
            }
        }

        private async Task<(int, ClaimsPrincipal, string)> AcquireTokensAsync(OpenidConnectPkceState openidClientPkceState, string code)
        {
            var tokenRequest = new TokenRequest
            {
                GrantType = IdentityConstants.GrantTypes.AuthorizationCode,
                Code = code,
                ClientId = openidClientPkceState.ClientId,
                RedirectUri = openidClientPkceState.CallBackUri,
            };

            var codeVerifierSecret = new CodeVerifierSecret
            {
                CodeVerifier = openidClientPkceState.CodeVerifier,
            };

            var oidcDiscovery = await GetOidcDiscoveryAsync(openidClientPkceState.OidcDiscoveryUri);

            var request = new HttpRequestMessage(HttpMethod.Post, oidcDiscovery.TokenEndpoint);
            request.Content = new FormUrlEncodedContent(tokenRequest.ToDictionary().AddToDictionary(codeVerifierSecret));

            var response = await httpClient.SendAsync(request);
            switch (response.StatusCode)
            {
                case HttpStatusCode.OK:
                    var result = await response.Content.ReadAsStringAsync();
                    var tokenResponse = result.ToObject<TokenResponse>();
                    tokenResponse.Validate(true);
                    if (tokenResponse.AccessToken.IsNullOrEmpty()) throw new ArgumentNullException(nameof(tokenResponse.AccessToken), tokenResponse.GetTypeName());
                    if (tokenResponse.ExpiresIn <= 0) throw new ArgumentNullException(nameof(tokenResponse.ExpiresIn), tokenResponse.GetTypeName());

                    var oidcDiscoveryKeySet = await GetOidcDiscoveryKeysAsync(openidClientPkceState.OidcDiscoveryUri);
                    (var idTokenPrincipal, _) = JwtHandler.ValidateToken(tokenResponse.IdToken, oidcDiscovery.Issuer, oidcDiscoveryKeySet.Keys, openidClientPkceState.ClientId, nameClaimType: globalOpenidClientPkceSettings.NameClaimType, roleClaimType: globalOpenidClientPkceSettings.RoleClaimType);

                    var nonce = idTokenPrincipal.Claims.Where(c => c.Type == JwtClaimTypes.Nonce).Select(c => c.Value).SingleOrDefault();
                    if (!openidClientPkceState.Nonce.Equals(nonce, StringComparison.Ordinal))
                    {
                        throw new SecurityException("Nonce do not match.");
                    }

                    return (tokenResponse.ExpiresIn, idTokenPrincipal, tokenResponse.AccessToken);

                case HttpStatusCode.BadRequest:
                    var resultBadRequest = await response.Content.ReadAsStringAsync();
                    var tokenResponseBadRequest = resultBadRequest.ToObject<TokenResponse>();
                    tokenResponseBadRequest.Validate(true);
                    throw new Exception($"Error login call back, Bad request. StatusCode={response.StatusCode}");

                default:
                    throw new Exception($"Error login call back, Status Code not expected. StatusCode={response.StatusCode}");
            }
        }

        private async Task<OidcDiscovery> GetOidcDiscoveryAsync(string oidcDiscoveryUri)
        {
            try
            {
                return await oidcDiscoveryHandler.GetOidcDiscoveryAsync(oidcDiscoveryUri);
            }
            catch (Exception ex)
            { 
                throw new Exception($"Failed to fetch Oidc Discovery from '{oidcDiscoveryUri}'.", ex);
            }
        }

        private async Task<JsonWebKeySet> GetOidcDiscoveryKeysAsync(string oidcDiscoveryUri)
        {
            try
            {
                return await oidcDiscoveryHandler.GetOidcDiscoveryKeysAsync(oidcDiscoveryUri);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to fetch Oidc Discovery Keys from discovery '{oidcDiscoveryUri}'.", ex);
            }
        }


        private async Task<string> SaveStateAsync(string oidcDiscoveryUri, string clientId, string callBackUri, string redirectUri, string codeVerifier = null, string nonce = null)
        {
            var state = RandomGenerator.GenerateNonce(32);
            var openidClientPkceState = new OpenidConnectPkceState
            {
                OidcDiscoveryUri = oidcDiscoveryUri,
                ClientId = clientId,
                CallBackUri = callBackUri,
                RedirectUri = redirectUri,
                CodeVerifier = codeVerifier,
                Nonce = nonce
            };
            await sessionStorage.SetItemAsync(state, openidClientPkceState);
            return state;
        }

        private async Task<OpenidConnectPkceState> GetState(string state, bool delete = true)
        {
            var openidClientPkceState = await sessionStorage.GetItemAsync<OpenidConnectPkceState>(state);
            if (delete)
            {
                await sessionStorage.RemoveItemAsync(state);
            }
            return openidClientPkceState;
        }


    }
}
