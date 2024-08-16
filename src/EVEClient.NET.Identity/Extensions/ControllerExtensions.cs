using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;

using EVEClient.NET.Identity.Defaults;

namespace EVEClient.NET.Identity.Extensions
{
    public static class ControllerExtensions
    {
        public static async Task<ChallengeResult> EveChallengeAsync(this Controller controller, string? returnUrl)
        {
            var provider = controller.HttpContext.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();
            var schemes = await provider.GetAllSchemesAsync();

            var schemeName = schemes.FirstOrDefault(x => x.Name == EveAuthenticationCookieDefaults.OAuth.DefaultOAuthAuthenticationSchemeName)?.Name;
            if (schemeName.IsPresent())
            {
                return controller.EveChallenge(returnUrl, schemeName);
            }

            throw new InvalidOperationException("No OAuth authentication scheme found for EVE Challange.");
        }

        private static ChallengeResult EveChallenge(this Controller controller, string? returnUrl, string scheme)
        {
            return new ChallengeResult(scheme, CreateChallengeAuthenticationProperties(returnUrl, scheme));
        }

        private static AuthenticationProperties CreateChallengeAuthenticationProperties(string? returnUrl, string scheme)
        {
            return new AuthenticationProperties
            {
                RedirectUri = EveConstants.OAuth.PostOAuthCallbackPath,
                Items =
                {
                    { "returnUrl", returnUrl },
                    { "scheme", scheme },
                }
            };
        }
    }
}
