using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.DependencyInjection;

using EVEClient.NET.Identity.Defaults;

namespace EVEClient.NET.Identity.Extensions
{
    public static class PageModelExtensions
    {
        public static async Task<ChallengeResult> EveChallengeAsync(this PageModel page, string? returnUrl)
        {
            var provider = page.HttpContext.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();
            var schemes = await provider.GetAllSchemesAsync();

            var schemeName = schemes.FirstOrDefault(x => x.Name == EveAuthenticationCookieDefaults.OAuth.DefaultOAuthAuthenticationSchemeName)?.Name;
            if (schemeName.IsPresent())
            {
                return page.EveChallenge(returnUrl, schemeName);
            }

            throw new InvalidOperationException("No OAuth authentication scheme found for EVE Challange.");
        }

        private static ChallengeResult EveChallenge(this PageModel page, string? returnUrl, string scheme)
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
