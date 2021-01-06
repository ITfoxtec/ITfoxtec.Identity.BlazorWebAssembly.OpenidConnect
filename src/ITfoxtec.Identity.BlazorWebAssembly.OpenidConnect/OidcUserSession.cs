using System;
using System.Collections.Generic;

namespace ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
{
    public class OidcUserSession
    {
        public DateTimeOffset ValidUntil { get; set; }
        public List<KeyValuePair<string, string>> Claims { get; set; }
        public string AuthenticationType { get; set; }
        public string IdToken { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public string SessionState { get; set; }
        public string OidcDiscoveryUri { get; set; }
        public string ClientId { get; set; }
    }
}
