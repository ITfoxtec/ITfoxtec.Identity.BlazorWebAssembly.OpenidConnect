using System.Collections.Generic;

namespace ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
{
    public class OpenidConnectPkceState
    {
        public string OidcDiscoveryUri { get; set; }
        public string ClientId { get; set; }
        public IEnumerable<string> Resources { get; set; }        
        public string CallBackUri { get; set; }
        public string RedirectUri { get; set; }
        public string CodeVerifier { get; set; }
        public string Nonce { get; set; }
    }
}
