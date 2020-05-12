using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
{
    public class AccessTokenMessageHandler : DelegatingHandler
    {
        private readonly NavigationManager navigationManager;
        private readonly OpenidConnectPkce openidConnectPkce;
        private readonly AuthenticationStateProvider authenticationStateProvider;

        public AccessTokenMessageHandler(NavigationManager navigationManager, OpenidConnectPkce openidConnectPkce, AuthenticationStateProvider authenticationStateProvider)
        {
            this.navigationManager = navigationManager;
            this.openidConnectPkce = openidConnectPkce;
            this.authenticationStateProvider = authenticationStateProvider;
        }

        public string[] AuthorizedUris { get; set; }

        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (GetBaseUriOrAuthorizedUris().Any(u => u.IsBaseOf(request.RequestUri)))
            {
                var accessToken = await (authenticationStateProvider as OidcAuthenticationStateProvider).GetAccessToken();
                if (accessToken.IsNullOrEmpty())
                {
                    await openidConnectPkce.LoginAsync();
                }
                request.Headers.Authorization = new AuthenticationHeaderValue(IdentityConstants.TokenTypes.Bearer, accessToken);
            }
            return await base.SendAsync(request, cancellationToken);
        }

        private IEnumerable<Uri> GetBaseUriOrAuthorizedUris()
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
