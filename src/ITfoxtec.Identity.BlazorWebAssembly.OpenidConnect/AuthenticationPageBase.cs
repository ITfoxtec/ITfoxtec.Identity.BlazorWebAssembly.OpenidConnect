using Microsoft.AspNetCore.Components;
using System;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
{
    public class AuthenticationPageBase : ComponentBase
    {
        [Inject]
        protected OpenidConnectPkce openidConnectPkce { get; set; }

        [Inject]
        protected NavigationManager navigationManager { get; set; }

        [Parameter]
        public string Action { get; set; }

        protected override async Task OnInitializedAsync()
        {
            if ("login_callback".Equals(Action, StringComparison.OrdinalIgnoreCase))
            {
                await openidConnectPkce.LoginCallBackAsync(navigationManager.Uri);
            }
            else if ("logout_callback".Equals(Action, StringComparison.OrdinalIgnoreCase))
            {
                await openidConnectPkce.LogoutCallBackAsync(navigationManager.Uri);
            }
            else
            {
                throw new Exception($"Action '{Action}' not supported.");
            }
        }
    }
}
