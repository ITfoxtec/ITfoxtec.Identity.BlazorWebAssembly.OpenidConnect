﻿using Blazored.SessionStorage;
using ITfoxtec.Identity.Discovery;
using ITfoxtec.Identity.Helpers;
using ITfoxtec.Identity.Messages;
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
        protected readonly OidcHelper oidcHelper;
        protected readonly AuthenticationStateProvider authenticationStateProvider;

        public OpenidConnectPkce(IServiceProvider serviceProvider, OpenidConnectPkceSettings globalOpenidClientPkceSettings, NavigationManager navigationManager, ISessionStorageService sessionStorage, OidcHelper oidcHelper, AuthenticationStateProvider authenticationStateProvider)
        {
            this.serviceProvider = serviceProvider;
            this.globalOpenidClientPkceSettings = globalOpenidClientPkceSettings;
            this.navigationManager = navigationManager;
            this.sessionStorage = sessionStorage;
            this.oidcHelper = oidcHelper;
            this.authenticationStateProvider = authenticationStateProvider;
        }

        /// <summary>
        /// Initiate login.
        /// </summary>
        /// <param name="openidClientPkceSettings">OPTIONAL. set the client settings.</param>
        /// <param name="loginHint">OPTIONAL. Hint to the Authorization Server about the login identifier the End-User might use to log in (if necessary). This hint can be used by an RP if it first asks the End-User for their e-mail address(or other identifier) and then wants to pass that value as a hint to the discovered authorization service.</param>
        /// <param name="uiLocales">OPTIONAL. End-User's preferred languages and scripts for the user interface, represented as a space-separated list of BCP47 [RFC5646] language tag values, ordered by preference. For instance, the value "fr-CA fr en" represents a preference for French as spoken in Canada, then French (without region), followed by English (without region).</param>
        /// <param name="prompt">OPTIONAL. Space delimited, case sensitive list of ASCII string values that specifies whether the Authorization Server prompts the End-User for reauthentication and consent.</param>       
        /// <param name="acrValues">OPTIONAL. Requested Authentication Context Class Reference values. Space-separated string that specifies the acr values that the Authorization Server is being requested to use for processing this Authentication Request, with the values appearing in order of preference.</param>
        public async Task LoginAsync(OpenidConnectPkceSettings openidClientPkceSettings = null, string loginHint = null, string uiLocales = null, string prompt = null, string acrValues = null)
        {
            try
            {
                openidClientPkceSettings = openidClientPkceSettings ?? globalOpenidClientPkceSettings;

                var nonce = RandomGenerator.GenerateNonce();
                var codeVerifier = RandomGenerator.Generate(64);

                ValidateResponseMode(openidClientPkceSettings.ResponseMode);
                var loginCallBackUri = new Uri(new Uri(navigationManager.BaseUri), openidClientPkceSettings.LoginCallBackPath).OriginalString;
                var state = await SaveStateAsync(openidClientPkceSettings, loginCallBackUri, navigationManager.Uri, codeVerifier: codeVerifier, nonce: nonce);

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
                if (!loginHint.IsNullOrWhiteSpace())
                {
                    authenticationRequest.LoginHint = loginHint;
                }
                if (!uiLocales.IsNullOrWhiteSpace())
                {
                    authenticationRequest.UiLocales = uiLocales;
                }
                if (!prompt.IsNullOrWhiteSpace())
                {
                    authenticationRequest.Prompt = prompt;
                }
                if (!acrValues.IsNullOrWhiteSpace())
                {
                    authenticationRequest.AcrValues = acrValues;
                }

                var codeChallengeRequest = new CodeChallengeSecret
                {
                    CodeChallenge = await codeVerifier.Sha256HashBase64urlEncodedAsync(),
                    CodeChallengeMethod = IdentityConstants.CodeChallengeMethods.S256,
                };

                var requestDictionary = authenticationRequest.ToDictionary().AddToDictionary(codeChallengeRequest);
                if(openidClientPkceSettings.Resources?.Count() > 0)
                {
                    var resourceRequest = new ResourceRequest
                    {
                        Resources = openidClientPkceSettings.Resources
                    };
                    requestDictionary = requestDictionary.AddToDictionary(resourceRequest);
                }

                var oidcDiscovery = await GetOidcDiscoveryAsync(openidClientPkceSettings.OidcDiscoveryUri);
                var authorizationUri = QueryHelpers.AddQueryString(oidcDiscovery.AuthorizationEndpoint, requestDictionary);
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
                if (openidClientPkceState != null)
                {
                    (var idTokenPrincipal, var tokenResponse) = await AcquireTokensAsync(openidClientPkceState, authenticationResponse.Code);

                    var sessionResponse = responseQuery.ToObject<SessionResponse>();
                    sessionResponse.Validate();

                    var validUntil = DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn.HasValue ? tokenResponse.ExpiresIn.Value : 0).AddSeconds(-globalOpenidClientPkceSettings.TokensExpiresBefore);
                    await (authenticationStateProvider as OidcAuthenticationStateProvider).CreateSessionAsync(validUntil, idTokenPrincipal, tokenResponse, sessionResponse.SessionState, openidClientPkceState);
                    navigationManager.NavigateTo(openidClientPkceState.RedirectUri, true);
                }
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

            var requestDictionary = tokenRequest.ToDictionary().AddToDictionary(codeVerifierSecret);
            if (openidClientPkceState.Resources?.Count() > 0)
            {
                var resourceRequest = new ResourceRequest
                {
                    Resources = openidClientPkceState.Resources
                };
                requestDictionary = requestDictionary.AddToDictionary(resourceRequest);
            }

            var request = new HttpRequestMessage(HttpMethod.Post, oidcDiscovery.TokenEndpoint);
            request.Content = new FormUrlEncodedContent(requestDictionary);

            using var response = await GetHttpClient().SendAsync(request);
            switch (response.StatusCode)
            {
                case HttpStatusCode.OK:
                    var result = await response.Content.ReadAsStringAsync();
                    var tokenResponse = result.ToObject<TokenResponse>();
                    tokenResponse.Validate(true);
                    if (tokenResponse.AccessToken.IsNullOrEmpty()) throw new ArgumentNullException(nameof(tokenResponse.AccessToken), tokenResponse.GetTypeName());
                    if (tokenResponse.ExpiresIn <= 0) throw new ArgumentNullException(nameof(tokenResponse.ExpiresIn), tokenResponse.GetTypeName());

                    var idTokenPrincipal = await oidcHelper.ValidateOidcWithUserInfoEndpoint(tokenResponse.IdToken, tokenResponse.AccessToken, openidClientPkceState.Nonce);
                    return (idTokenPrincipal, tokenResponse);

                default:
                    var resultBadRequest = await response.Content.ReadAsStringAsync();
                    var tokenResponseBadRequest = resultBadRequest.ToObject<TokenResponse>();
                    tokenResponseBadRequest.Validate(true);
                    throw new Exception($"Error login call back, unexpected status code. StatusCode={response.StatusCode}");
            }
        }

        public async Task<OidcUserSession> HandleRefreshTokenAsync(OidcUserSession userSession)
        {
            if (!userSession.RefreshToken.IsNullOrEmpty() && userSession.ValidUntil < DateTimeOffset.UtcNow.AddSeconds(globalOpenidClientPkceSettings.TokensExpiresBefore))
            {
                var subject = userSession.Claims.Where(c => c.Type == globalOpenidClientPkceSettings.NameClaimType).Select(c => c.Value).SingleOrDefault();
                (var idTokenPrincipal, var tokenResponse) = await AcquireRefreshTokensAsync(userSession.OidcDiscoveryUri, userSession.ClientId, subject, userSession.RefreshToken);

                var validUntil = DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn.HasValue ? tokenResponse.ExpiresIn.Value : 0).AddSeconds(-globalOpenidClientPkceSettings.TokensExpiresBefore);
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

            var response = await GetHttpClient().SendAsync(request);
            switch (response.StatusCode)
            {
                case HttpStatusCode.OK:
                    try
                    {
                        var result = await response.Content.ReadAsStringAsync();
                        var tokenResponse = result.ToObject<TokenResponse>();
                        tokenResponse.Validate(true);
                        if (tokenResponse.AccessToken.IsNullOrEmpty()) throw new ArgumentNullException(nameof(tokenResponse.AccessToken), tokenResponse.GetTypeName());
                        if (tokenResponse.ExpiresIn <= 0) throw new ArgumentNullException(nameof(tokenResponse.ExpiresIn), tokenResponse.GetTypeName());

                        var idTokenPrincipal = await oidcHelper.ValidateOidcWithUserInfoEndpoint(tokenResponse.IdToken, tokenResponse.AccessToken);

                        if (!subject.IsNullOrEmpty() && subject != idTokenPrincipal.Claims.Where(c => c.Type == globalOpenidClientPkceSettings.NameClaimType).Single().Value)
                        {
                            throw new Exception("New principal has invalid sub claim.");
                        }

                        if (tokenResponse.RefreshToken.IsNullOrEmpty())
                        {
                            tokenResponse.RefreshToken = refreshToken;
                        }

                        return (idTokenPrincipal, tokenResponse);
                    }
                    catch (ResponseErrorException rex)
                    {
                        throw new TokenUnavailableException(rex.Message, rex);
                    }

                case HttpStatusCode.BadRequest:
                    try
                    {
                        var resultBadRequest = await response.Content.ReadAsStringAsync();
                        var tokenResponseBadRequest = resultBadRequest.ToObject<TokenResponse>();
                        tokenResponseBadRequest.Validate(true);
                        throw new TokenUnavailableException($"Error, Bad request. StatusCode={response.StatusCode}");
                    }
                    catch (ResponseErrorException rex)
                    {
                        throw new TokenUnavailableException(rex.Message, rex);
                    }

                default:
                    throw new TokenUnavailableException($"Error, Status Code not expected. StatusCode={response.StatusCode}");
            }
        }

        private HttpClient GetHttpClient()
        {
            var httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();
            return httpClientFactory.CreateClient();
        }

        /// <summary>
        /// Initiate logout.
        /// </summary>
        /// <param name="openidClientPkceSettings">OPTIONAL. set the client settings.</param>
        public async Task LogoutAsync(OpenidConnectPkceSettings openidClientPkceSettings = null)
        {
            try
            {
                openidClientPkceSettings = openidClientPkceSettings ?? globalOpenidClientPkceSettings;

                var logoutCallBackUri = new Uri(new Uri(navigationManager.BaseUri), openidClientPkceSettings.LogoutCallBackPath).OriginalString;
                var state = await SaveStateAsync(openidClientPkceSettings, logoutCallBackUri, navigationManager.Uri);

                var idTokenHint = await (authenticationStateProvider as OidcAuthenticationStateProvider).GetIdToken(readInvalidSession: true);
                if(idTokenHint.IsNullOrEmpty())
                {
                    navigationManager.NavigateTo(logoutCallBackUri, true);
                }
                var rpInitiatedLogoutRequest = new RpInitiatedLogoutRequest
                {
                    IdTokenHint = idTokenHint,
                    PostLogoutRedirectUri = logoutCallBackUri,
                    State = state
                };

                var nameValueCollection = rpInitiatedLogoutRequest.ToDictionary();
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
                var rpInitiatedLogoutResponse = GetResponseQuery(responseUrl).ToObject<RpInitiatedLogoutResponse>();
                rpInitiatedLogoutResponse.Validate();
                if (rpInitiatedLogoutResponse.State.IsNullOrEmpty()) throw new ArgumentNullException(nameof(rpInitiatedLogoutResponse.State), rpInitiatedLogoutResponse.GetTypeName());

                var openidClientPkceState = await GetState(rpInitiatedLogoutResponse.State);
                if (openidClientPkceState != null)
                {
                    await (authenticationStateProvider as OidcAuthenticationStateProvider).DeleteSessionAsync();
                    navigationManager.NavigateTo(openidClientPkceState.RedirectUri, true);
                }
            }
            catch (Exception ex)
            {
                throw new SecurityException($"Failed to handle logout call back, response URL '{responseUrl}'.", ex);
            }
        }

        private Dictionary<string, string> GetResponseQuery(string responseUrl)
        {
            var rUri = new Uri(responseUrl);                        
            if (rUri.Query.IsNullOrWhiteSpace() && rUri.Fragment.IsNullOrWhiteSpace())
            {
                throw new SecurityException("Invalid response URL.");
            }
            return QueryHelpers.ParseQuery(!rUri.Query.IsNullOrWhiteSpace() ? rUri.Query.TrimStart('?') : rUri.Fragment.TrimStart('#')).ToDictionary();
        }

        private async Task<OidcDiscovery> GetOidcDiscoveryAsync(string oidcDiscoveryUri)
        {
            try
            {
                var oidcDiscoveryHandler = serviceProvider.GetService<OidcDiscoveryHandler>();
                oidcDiscoveryHandler.SetDefaultOidcDiscoveryUri(oidcDiscoveryUri);
                return await oidcDiscoveryHandler.GetOidcDiscoveryAsync(oidcDiscoveryUri);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to fetch OIDC Discovery from '{oidcDiscoveryUri}'.", ex);
            }
        }

        private async Task<string> SaveStateAsync(OpenidConnectPkceSettings openidConnectPkceSettings, string callBackUri, string redirectUri, string codeVerifier = null, string nonce = null)
        {
            var state = RandomGenerator.GenerateNonce(32);
            var openidClientPkceState = new OpenidConnectPkceState
            {
                OidcDiscoveryUri = openidConnectPkceSettings.OidcDiscoveryUri,
                ClientId = openidConnectPkceSettings.ClientId,
                Resources = openidConnectPkceSettings.Resources,
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
