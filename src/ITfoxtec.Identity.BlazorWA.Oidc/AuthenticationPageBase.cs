using Microsoft.AspNetCore.Components;
using System;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
{
    public class AuthenticationPageBase : ComponentBase
    {
        [Inject]
        protected OpenidConnectPkceSettings openidConnectPkceSettings { get; set; }

        [Inject]
        protected OpenidConnectPkce openidConnectPkce { get; set; }

        [Inject]
        protected NavigationManager navigationManager { get; set; }

        [Parameter]
        public string Action { get; set; }

        protected override async Task OnInitializedAsync()
        {
            if (openidConnectPkceSettings.LoginCallBackPage.Equals(Action, StringComparison.OrdinalIgnoreCase))
            {
                await openidConnectPkce.LoginCallBackAsync(navigationManager.Uri);
            }
            else if (openidConnectPkceSettings.LogoutCallBackPage.Equals(Action, StringComparison.OrdinalIgnoreCase))
            {
                await openidConnectPkce.LogoutCallBackAsync(navigationManager.Uri);
            }
            else if (openidConnectPkceSettings.FrontChannelLogoutPage.Equals(Action, StringComparison.OrdinalIgnoreCase))
            {
                await openidConnectPkce.FrontChannelLogoutAsync(navigationManager.Uri);
            }
            else
            {
                throw new Exception($"Action '{Action}' not supported.");
            }
        }
    }
}
