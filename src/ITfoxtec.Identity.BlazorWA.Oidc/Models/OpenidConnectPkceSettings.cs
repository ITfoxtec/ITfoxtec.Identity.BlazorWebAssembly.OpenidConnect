using System;
using System.Collections.Generic;

namespace ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
{
    public class OpenidConnectPkceSettings
    {
        /// <summary>
        /// Gets or sets the Authority to use when making OpenIdConnect calls.
        /// </summary>
        public string Authority { get; set; }

        /// <summary>
        /// The OIDC Discovery URI.
        /// </summary>
        public string OidcDiscoveryUri => new Uri(new Uri(Authority), IdentityConstants.OidcDiscovery.Path).OriginalString;

        /// <summary>
        /// Gets or sets the 'client_id'
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the 'response_type'.
        /// </summary>
        public string ResponseType { get; private set; } = IdentityConstants.ResponseTypes.Code;

        /// <summary>
        /// Gets or sets the 'response_mode'.
        /// </summary>
        public string ResponseMode { get; set; } = IdentityConstants.ResponseModes.Fragment;

        /// <summary>
        /// Login call back path.
        /// </summary>
        public string LoginCallBackPath { get; set; } = "authentication/login_callback";

        /// <summary>
        /// Logout call back path.
        /// </summary>
        public string LogoutCallBackPath { get; set; } = "authentication/logout_callback";

        /// <summary>
        /// Gets or sets the space separated list of scopes to request.
        /// </summary>
        public string Scope { get; set; } 

        private IEnumerable<string> DefaultScope = new[] { IdentityConstants.DefaultOidcScopes.OpenId };

        public IEnumerable<string> AllScope 
        { 
            get 
            {
                return Scope == null ? DefaultScope : DefaultScope.ConcatOnce(Scope.ToSpaceList());
            }
        }

        /// <summary>
        /// Gets or sets the list of resources to request.
        /// </summary>
        public IEnumerable<string> Resources { get; set; }

        /// <summary>
        /// Gets or sets a string that defines the name claim type. Default sub.
        /// </summary>
        public string NameClaimType { get; set; } = JwtClaimTypes.Subject;

        /// <summary>
        /// Gets or sets the string that defines the role claim type. Default role.
        /// </summary>
        public string RoleClaimType { get; set; } = JwtClaimTypes.Role;

        /// <summary>
        /// Tokens expires before actual expiration time, in seconds. Default 30 seconds.
        /// </summary>
        public int TokensExpiresBefore { get; set; } = 30;
    }
}
