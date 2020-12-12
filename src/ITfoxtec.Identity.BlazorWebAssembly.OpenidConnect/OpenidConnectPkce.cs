using Blazored.SessionStorage;
using ITfoxtec.Identity.Discovery;
using ITfoxtec.Identity.Models;
using ITfoxtec.Identity.Messages;
using ITfoxtec.Identity.Tokens;
using ITfoxtec.Identity.Util;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
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
        protected readonly IServiceProvider serviceProvider;
        protected readonly OpenidConnectPkceSettings globalOpenidClientPkceSettings;
        protected readonly NavigationManager navigationManager;
        protected readonly ISessionStorageService sessionStorage;
        protected readonly AuthenticationStateProvider authenticationStateProvider;

        public OpenidConnectPkce(IServiceProvider serviceProvider, OpenidConnectPkceSettings globalOpenidClientPkceSettings, NavigationManager navigationManager, ISessionStorageService sessionStorage, AuthenticationStateProvider authenticationStateProvider)
        {
            this.serviceProvider = serviceProvider;
            this.globalOpenidClientPkceSettings = globalOpenidClientPkceSettings;
            this.navigationManager = navigationManager;
            this.sessionStorage = sessionStorage;
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

                if(openidClientPkceSettings.Resources?.Count() > 0)
                {
                    var resourceRequest = new ResourceRequest
                    {
                        Resources = openidClientPkceSettings.Resources
                    };
                    nameValueCollection = nameValueCollection.AddToDictionary(resourceRequest);
                }

                var oidcDiscovery = await GetOidcDiscoveryAsync(openidClientPkceSettings.OidcDiscoveryUri);
                var authorizationUri = QueryHelpers.AddQueryString(oidcDiscovery.AuthorizationEndpoint, nameValueCollection);
                navigationManager.NavigateTo(authorizationUri, true);

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
                var responseQuery = GetResponseQuery(responseUrl);
                var authenticationResponse = responseQuery.ToObject<AuthenticationResponse>();
                authenticationResponse.Validate();
                if (authenticationResponse.State.IsNullOrEmpty()) throw new ArgumentNullException(nameof(authenticationResponse.State), authenticationResponse.GetTypeName());

                var openidClientPkceState = await GetState(authenticationResponse.State);
                if (openidClientPkceState == null)
                {
                    throw new SecurityException($"State '{authenticationResponse.State}' do not exist.");
                }

                (var idTokenPrincipal, var tokenResponse) = await AcquireTokensAsync(openidClientPkceState, authenticationResponse.Code);

                var sessionResponse = responseQuery.ToObject<SessionResponse>();
                sessionResponse.Validate();

                var validUntil = DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn).AddSeconds(-globalOpenidClientPkceSettings.TokensExpiresBefore);
                await (authenticationStateProvider as OidcAuthenticationStateProvider).CreateSessionAsync(validUntil, idTokenPrincipal, tokenResponse, sessionResponse.SessionState, openidClientPkceState);
                navigationManager.NavigateTo(openidClientPkceState.RedirectUri, true);
            }
            catch (Exception ex)
            {
                throw new SecurityException($"Failed to handle login call back, response URL '{responseUrl}'.", ex);
            }
        }

        private async Task<(ClaimsPrincipal idTokenPrincipal, TokenResponse tokenResponse)> AcquireTokensAsync(OpenidConnectPkceState openidClientPkceState, string code)
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

            var httpClient = serviceProvider.GetService<HttpClient>();
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

                    // .NET 5.0 error, System.Security.Cryptography.RSA.Create() - System.PlatformNotSupportedException: System.Security.Cryptography.Algorithms is not supported on this platform.
                    // https://github.com/dotnet/aspnetcore/issues/26123
                    // https://github.com/dotnet/runtime/issues/40074

                    (var idTokenPrincipal, _) = JwtHandler.ValidateToken(tokenResponse.IdToken, oidcDiscovery.Issuer, oidcDiscoveryKeySet.Keys.ToMSJsonWebKeys(), openidClientPkceState.ClientId,
                        nameClaimType: globalOpenidClientPkceSettings.NameClaimType, roleClaimType: globalOpenidClientPkceSettings.RoleClaimType
#if NET50
                        , validateSigningKey: false
#endif
                        );

                    var nonce = idTokenPrincipal.Claims.Where(c => c.Type == JwtClaimTypes.Nonce).Select(c => c.Value).SingleOrDefault();
                    if (!openidClientPkceState.Nonce.Equals(nonce, StringComparison.Ordinal))
                    {
                        throw new SecurityException("Nonce do not match.");
                    }

                    return (idTokenPrincipal, tokenResponse);

                case HttpStatusCode.BadRequest:
                    var resultBadRequest = await response.Content.ReadAsStringAsync();
                    var tokenResponseBadRequest = resultBadRequest.ToObject<TokenResponse>();
                    tokenResponseBadRequest.Validate(true);
                    throw new Exception($"Error login call back, Bad request. StatusCode={response.StatusCode}");

                default:
                    throw new Exception($"Error login call back, Status Code not expected. StatusCode={response.StatusCode}");
            }
        }

        public async Task<OidcUserSession> HandleRefreshTokenAsync(OidcUserSession userSession)
        {
            if (!userSession.RefreshToken.IsNullOrEmpty() && userSession.ValidUntil < DateTimeOffset.UtcNow.AddSeconds(globalOpenidClientPkceSettings.TokensExpiresBefore))
            {
                var subject = userSession.Claims.Where(c => c.Key == JwtClaimTypes.Subject).Select(c => c.Value).SingleOrDefault();
                (var idTokenPrincipal, var tokenResponse) = await AcquireRefreshTokensAsync(userSession.OidcDiscoveryUri, userSession.ClientId, subject, userSession.RefreshToken);

                var validUntil = DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn).AddSeconds(-globalOpenidClientPkceSettings.TokensExpiresBefore);
                return await (authenticationStateProvider as OidcAuthenticationStateProvider).UpdateSessionAsync(validUntil, idTokenPrincipal, tokenResponse, userSession.SessionState, userSession);
            }

            return userSession;
        }

        private async Task<(ClaimsPrincipal idTokenPrincipal, TokenResponse tokenResponse)> AcquireRefreshTokensAsync(string oidcDiscoveryUri, string clientId, string subject, string refreshToken)
        {
            var tokenRequest = new TokenRequest
            {
                GrantType = IdentityConstants.GrantTypes.RefreshToken,
                RefreshToken = refreshToken,
                ClientId = clientId,
            };

            var oidcDiscovery = await GetOidcDiscoveryAsync(oidcDiscoveryUri);

            var request = new HttpRequestMessage(HttpMethod.Post, oidcDiscovery.TokenEndpoint);
            request.Content = new FormUrlEncodedContent(tokenRequest.ToDictionary());

            var httpClient = serviceProvider.GetService<HttpClient>();
            var response = await httpClient.SendAsync(request);
            switch (response.StatusCode)
            {
                case HttpStatusCode.OK:
                    var result = await response.Content.ReadAsStringAsync();
                    var tokenResponse = result.ToObject<TokenResponse>();
                    tokenResponse.Validate(true);
                    if (tokenResponse.AccessToken.IsNullOrEmpty()) throw new ArgumentNullException(nameof(tokenResponse.AccessToken), tokenResponse.GetTypeName());
                    if (tokenResponse.ExpiresIn <= 0) throw new ArgumentNullException(nameof(tokenResponse.ExpiresIn), tokenResponse.GetTypeName());

                    var oidcDiscoveryKeySet = await GetOidcDiscoveryKeysAsync(oidcDiscoveryUri);

                    // .NET 5.0 error, System.Security.Cryptography.RSA.Create() - System.PlatformNotSupportedException: System.Security.Cryptography.Algorithms is not supported on this platform.
                    // https://github.com/dotnet/aspnetcore/issues/26123
                    // https://github.com/dotnet/runtime/issues/40074

                    (var idTokenPrincipal, _) = JwtHandler.ValidateToken(tokenResponse.IdToken, oidcDiscovery.Issuer, oidcDiscoveryKeySet.Keys, clientId
#if NET50
                        , validateSigningKey: false
#endif
                        );

                    if (!subject.IsNullOrEmpty() && subject != idTokenPrincipal.Claims.Where(c => c.Type == JwtClaimTypes.Subject).Single().Value)
                    {
                        throw new Exception("New principal has invalid sub claim.");
                    }

                    return (idTokenPrincipal, tokenResponse);

                case HttpStatusCode.BadRequest:
                    var resultBadRequest = await response.Content.ReadAsStringAsync();
                    var tokenResponseBadRequest = resultBadRequest.ToObject<TokenResponse>();
                    tokenResponseBadRequest.Validate(true);
                    throw new Exception($"Error, Bad request. StatusCode={response.StatusCode}");

                default:
                    throw new Exception($"Error, Status Code not expected. StatusCode={response.StatusCode}");
            }
        }

        public async Task LogoutAsync(OpenidConnectPkceSettings openidClientPkceSettings = null)
        {
            try
            {
                openidClientPkceSettings = openidClientPkceSettings ?? globalOpenidClientPkceSettings;

                var logoutCallBackUri = new Uri(new Uri(navigationManager.BaseUri), openidClientPkceSettings.LogoutCallBackPath).OriginalString;
                var state = await SaveStateAsync(openidClientPkceSettings.OidcDiscoveryUri, openidClientPkceSettings.ClientId, logoutCallBackUri, navigationManager.Uri);

                var idTokenHint = await (authenticationStateProvider as OidcAuthenticationStateProvider).GetIdToken(readInvalidSession: true);
                if(idTokenHint.IsNullOrEmpty())
                {
                    navigationManager.NavigateTo(logoutCallBackUri, true);
                }
                var endSessionRequest = new EndSessionRequest
                {
                    IdTokenHint = idTokenHint,
                    PostLogoutRedirectUri = logoutCallBackUri,
                    State = state
                };

                var nameValueCollection = endSessionRequest.ToDictionary();
                var oidcDiscovery = await GetOidcDiscoveryAsync(openidClientPkceSettings.OidcDiscoveryUri);
                var endSessionEndpointUri = QueryHelpers.AddQueryString(oidcDiscovery.EndSessionEndpoint, nameValueCollection);
                navigationManager.NavigateTo(endSessionEndpointUri, true);
            }
            catch (Exception ex)
            {
                throw new SecurityException($"Failed to end session, Authority '{openidClientPkceSettings.Authority}'.", ex);
            }
        }

        public async Task LogoutCallBackAsync(string responseUrl)
        {
            try
            {
                var endSessionResponse = GetResponseQuery(responseUrl).ToObject<EndSessionResponse>();
                endSessionResponse.Validate();
                if (endSessionResponse.State.IsNullOrEmpty()) throw new ArgumentNullException(nameof(endSessionResponse.State), endSessionResponse.GetTypeName());

                var openidClientPkceState = await GetState(endSessionResponse.State);
                if (openidClientPkceState == null)
                {
                    throw new SecurityException($"State '{endSessionResponse.State}' do not exist.");
                }

                await (authenticationStateProvider as OidcAuthenticationStateProvider).DeleteSessionAsync();
                navigationManager.NavigateTo(openidClientPkceState.RedirectUri, true);
            }
            catch (Exception ex)
            {
                throw new SecurityException($"Failed to handle logout call back, response URL '{responseUrl}'.", ex);
            }
        }

        private Dictionary<string, string> GetResponseQuery(string responseUrl)
        {
            var responseSplit = responseUrl.Split(responseUrl.Contains('#') ? '#' : '?');
            if (responseUrl.Count() <= 1)
            {
                throw new SecurityException("Invalid response URL.");
            }
            return QueryHelpers.ParseQuery(responseSplit[1]).ToDictionary();
        }

        private async Task<OidcDiscovery> GetOidcDiscoveryAsync(string oidcDiscoveryUri)
        {
            try
            {
                var oidcDiscoveryHandler = serviceProvider.GetService<OidcDiscoveryHandler>();
                return await oidcDiscoveryHandler.GetOidcDiscoveryAsync(oidcDiscoveryUri);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to fetch OIDC Discovery from '{oidcDiscoveryUri}'.", ex);
            }
        }

        private async Task<JsonWebKeySet> GetOidcDiscoveryKeysAsync(string oidcDiscoveryUri)
        {
            try
            {
                var oidcDiscoveryHandler = serviceProvider.GetService<OidcDiscoveryHandler>();
                return await oidcDiscoveryHandler.GetOidcDiscoveryKeysAsync(oidcDiscoveryUri);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to fetch OIDC Discovery Keys from discovery '{oidcDiscoveryUri}'.", ex);
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
