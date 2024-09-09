using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;

using EVEClient.NET.Identity.Defaults;

namespace EVEClient.NET.Identity.Extensions
{
    public static class ControllerExtensions
    {
        /// <summary>
        /// Returns an <see cref="ActionResult"/> that on execution invokes <see cref="M:HttpContext.ChallengeAsync"/>.
        /// </summary>
        /// <param name="controller">The <see cref="Controller"/>.</param>
        /// <param name="returnUrl">The full path or absolute URI to be used as an http redirect after successful EVE authentication.</param>
        /// <returns>The <see cref="Task"/> that present <see cref="ChallengeResult"/>.</returns>
        public static async Task<ChallengeResult> EveChallengeAsync(this Controller controller, string? returnUrl)
        {
            var provider = controller.HttpContext.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();
            var schemes = await provider.GetAllSchemesAsync();

            var schemeName = schemes.FirstOrDefault(x => x.Name == EveAuthenticationCookieDefaults.OAuth.DefaultOAuthSchemeName)?.Name;
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
