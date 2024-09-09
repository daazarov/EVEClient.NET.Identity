using System.Diagnostics;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Services;

namespace EVEClient.NET.Identity.Extensions
{
    public static class HttpContextExtensions
    {
        [DebuggerStepThrough]
        public static bool IsPrimaryIdentityEnable(this HttpContext context)
        {
            return context.RequestServices.GetRequiredService<IOptions<EveAuthenticationOptions>>().Value.IdentityMode == IdentityMode.PrimaryIdentity;
        }

        [DebuggerStepThrough]
        public static bool IsSecondaryIdentityEnable(this HttpContext context)
        { 
            return context.RequestServices.GetRequiredService<IOptions<EveAuthenticationOptions>>().Value.IdentityMode == IdentityMode.SecondaryIdentity;
        }

        [DebuggerStepThrough]
        public static bool IsMixedIdentityEnable(this HttpContext context)
        { 
            return context.RequestServices.GetRequiredService<IOptions<EveAuthenticationOptions>>().Value.IdentityMode == IdentityMode.MixedIdentity;
        }

        [DebuggerStepThrough]
        public static bool SignOutCalled(this HttpContext context)
        { 
            return context.Items.ContainsKey(EveConstants.SingOutKey);
        }

        public static async Task<AuthenticationScheme> GetEveCookieAuthenticationScheme(this HttpContext context)
        {
            var options = context.RequestServices.GetRequiredService<IOptions<EveAuthenticationOptions>>().Value;
            var schemes = context.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();

            if (options.CookieAuthenticationScheme.IsPresent())
            {
                var scheme = await schemes.GetSchemeAsync(options.CookieAuthenticationScheme);
                if (scheme != null)
                {
                    return scheme;
                }
            }

            throw new InvalidOperationException("No CookieAuthenticationScheme configured on EVEAuthenticationOptions or scheme wasn't found.");
        }

        public static async Task<string> GetEveCookieAuthenticationSchemeName(this HttpContext context)
        {
            return (await context.GetEveCookieAuthenticationScheme()).Name;
        }

        public static async Task<AuthenticationScheme> GetEveCookieExternalAuthenticationScheme(this HttpContext context)
        {
            var options = context.RequestServices.GetRequiredService<IOptions<EveAuthenticationOptions>>().Value;
            var schemes = context.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();

            if (options.CookieExternalAuthenticationScheme.IsPresent())
            {
                var scheme = await schemes.GetSchemeAsync(options.CookieExternalAuthenticationScheme);
                if (scheme != null)
                {
                    return scheme;
                }
            }

            throw new InvalidOperationException("No CookieExternalAuthenticationScheme configured on EVEAuthenticationOptions or scheme wasn't found.");
        }

        /// <summary>
        /// Authenticates the request using the EVE scheme and returns the value for the access token.
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <returns>Access token value.</returns>
        /// <remarks>
        /// Uses <see cref="AuthenticationProperties"/> if <see cref="EveAuthenticationOptions.UseCookieStorage"/> option is enabled. 
        /// Otherwise the token will be retrieved from the <see cref="Stores.IAccessTokenStore"/>.
        /// </remarks>
        public static async Task<string?> GetEveAccessTokenAsync(this HttpContext context)
        {
            var tokenResult = await context.GetTokenService().RequestAccessToken(context, await context.GetEveCookieAuthenticationSchemeName());

            return tokenResult.TryGetToken(out var token) ? token.Value : null;
        }

        /// <summary>
        /// Authenticates the request using the EVE scheme and returns the value for the refresh token.
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <returns>Refresh token value.</returns>
        /// <remarks>
        /// Uses <see cref="AuthenticationProperties"/> if <see cref="EveAuthenticationOptions.UseCookieStorage"/> option is enabled. 
        /// Otherwise the token will be retrieved from the <see cref="Stores.IRefreshTokenStore"/>.
        /// </remarks>
        public static async Task<string?> GetEveRefreshTokenAsync(this HttpContext context)
        {
            var tokenResult = await context.GetTokenService().RequestRefreshToken(context, await context.GetEveCookieAuthenticationSchemeName());

            return tokenResult.TryGetToken(out var token) ? token : null;
        }

        /// <summary>
        /// Sign out a principal for the EVE authentication scheme.
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <returns>The <see cref="Task"/>.</returns>
        public static async Task EveSingOutAsync(this HttpContext context)
        {
            context.Items[EveConstants.SingOutKey] = true;

            await context.SignOutAsync(await context.GetEveCookieAuthenticationSchemeName());
        }

        private static ITokenService GetTokenService(this HttpContext context)
        {
            return context.RequestServices.GetRequiredService<ITokenService>();
        }
    }
}
