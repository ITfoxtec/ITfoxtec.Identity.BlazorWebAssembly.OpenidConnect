using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
{
    public class AccessTokenMessageHandler : DelegatingHandler
    {
        protected readonly NavigationManager navigationManager;
        protected readonly OpenidConnectPkce openidConnectPkce;
        protected readonly AuthenticationStateProvider authenticationStateProvider;

        public AccessTokenMessageHandler(NavigationManager navigationManager, OpenidConnectPkce openidConnectPkce, AuthenticationStateProvider authenticationStateProvider)
        {
            this.navigationManager = navigationManager;
            this.openidConnectPkce = openidConnectPkce;
            this.authenticationStateProvider = authenticationStateProvider;
        }

        public string[] AuthorizedUris { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (GetBaseUriOrAuthorizedUris().Any(u => u.IsBaseOf(request.RequestUri)))
            {
                var accessToken = await (authenticationStateProvider as OidcAuthenticationStateProvider).GetAccessToken();
                if (accessToken.IsNullOrEmpty())
                {
                    throw new AuthenticationException("Access token is not available.");                    
                }
                request.Headers.Authorization = new AuthenticationHeaderValue(IdentityConstants.TokenTypes.Bearer, accessToken);
            }
            return await base.SendAsync(request, cancellationToken);
        }

        protected virtual IEnumerable<Uri> GetBaseUriOrAuthorizedUris()
        {
            if(AuthorizedUris?.Count() > 0)
            {
                return AuthorizedUris.Select(u => new Uri(u));
            }
            else
            {
                return new[] { new Uri(navigationManager.BaseUri) };
            }
        }
    }
}
