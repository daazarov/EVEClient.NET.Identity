using System.Security.Claims;
using Microsoft.Extensions.Options;

namespace EVEClient.NET.Identity.Configuration
{
    public class ConfigurePrimaryIdentitySelector : IPostConfigureOptions<EveAuthenticationOptions>
    {
        public void PostConfigure(string? name, EveAuthenticationOptions options)
        {
            switch (options.IdentityMode)
            {
                case IdentityMode.PrimaryIdentity:
                    ClaimsPrincipal.PrimaryIdentitySelector = IdentityModeSelectors.PrimaryMode.SelectPrimaryIdentity;
                    break;
                case IdentityMode.SecondaryIdentity:
                    ClaimsPrincipal.PrimaryIdentitySelector = IdentityModeSelectors.SecondaryMode.SelectPrimaryIdentity;
                    break;
                case IdentityMode.MixedIdentity:
                    ClaimsPrincipal.PrimaryIdentitySelector = IdentityModeSelectors.MixedMode.SelectPrimaryIdentity;
                    break;
            }
        }
    }
}
