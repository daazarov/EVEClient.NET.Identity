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

        public static async Task<EveAuthenticationContext?> GetCurrentEveAuthenticationContextAsync(this HttpContext context)
        {
            var identity = context.User.GetEveIdentity();

            if (identity is not null && identity.IsAuthenticated)
            {
                var userSession = context.RequestServices.GetRequiredService<IUserSession>();

                var sessionId = await userSession.GetCurrentSessionIdAsync() ?? throw new InvalidOperationException("Session ID can not be null or empty.");
                var subjectId = await userSession.GetCurrentSubjectIdAsync() ?? throw new InvalidOperationException("Subject ID can not be null or empty.");
                var accessTokenReferenceKey = await userSession.GetAccessTokenReferenceKeyAsync() ?? throw new InvalidOperationException("Access token reference key can not be null or empty.");
                var refreshTokenReferenceKey = await userSession.GetRefreshTokenReferenceKeyAsync() ?? throw new InvalidOperationException("Refresh token reference key can not be null or empty.");

                return new EveAuthenticationContext
                { 
                    SessionId = sessionId,
                    SubjectId = subjectId,
                    AccessTokenReferenceKey = accessTokenReferenceKey,
                    RefreshTokenReferenceKey = refreshTokenReferenceKey
                };
            }

            return null;
        }

        public static async Task EveSingOutAsync(this HttpContext context)
        {
            context.Items[EveConstants.SingOutKey] = true;

            await context.SignOutAsync(await context.GetEveCookieAuthenticationSchemeName());
        }
    }
}
