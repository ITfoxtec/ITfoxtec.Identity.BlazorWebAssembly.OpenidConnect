using ITfoxtec.Identity;
using Microsoft.AspNetCore.Authorization;

namespace BlazorWebAssemblyOidcSample.Server.Policys
{
    public class AccessPolicyAttribute : AuthorizeAttribute
    {
        private static string _name = nameof(AccessPolicyAttribute);

        public AccessPolicyAttribute() : base(_name)
        { }

        public static void AddPolicy(AuthorizationOptions options)
        {
            options.AddPolicy(_name, configurePolicy =>
            {
                configurePolicy.RequireScope("blazorweba_oidcpkce_sample:access");
            });
        }
    }
}
