using EVEClient.NET.Extensions;
using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Defaults;
using EVEClient.NET.Identity.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace EVEClient.NET.Identity.Extensions
{
    public static class HttpContextExtensions
    {
        public static bool IsPrimaryIdentityEnable(this HttpContext context)
        {
            return context.RequestServices.GetRequiredService<IOptions<EveAuthenticationOptions>>().Value.IdentityMode == IdentityMode.PrimaryIdentity;
        }

        public static bool IsSecondaryIdentityEnable(this HttpContext context)
        { 
            return context.RequestServices.GetRequiredService<IOptions<EveAuthenticationOptions>>().Value.IdentityMode == IdentityMode.SecondaryIdentity;
        }

        public static bool IsMixedIdentityEnable(this HttpContext context)
        { 
            return context.RequestServices.GetRequiredService<IOptions<EveAuthenticationOptions>>().Value.IdentityMode == IdentityMode.MixedIdentity;
        }

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
            
            var defaultScheme = await schemes.GetDefaultAuthenticateSchemeAsync();
            if (defaultScheme == null)
            {
                throw new InvalidOperationException("No DefaultAuthenticateScheme found or no AuthenticationScheme configured on EVEAuthenticationOptions.");
            }

            return defaultScheme;
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

            throw new InvalidOperationException();
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
                var refreshTokenReferenceKey = await userSession.GetAccessTokenReferenceKeyAsync() ?? throw new InvalidOperationException("Refresh token reference key can not be null or empty.");

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

        public static async Task<ChallengeResult> EveChallengeAsync(this HttpContext context, string? returnUrl)
        {
            var provider = context.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();
            var schemes = await provider.GetAllSchemesAsync();

            var schemeName = schemes.FirstOrDefault(x => x.DisplayName == "EVEOnline")?.Name;
            if (schemeName.IsPresent())
            {
                return context.EveChallenge(returnUrl, schemeName);
            }

            throw new InvalidOperationException();
        }

        public static Task InitEveChallengeAsync(this HttpContext context, string? returnUrl)
        { 
            return context.InitEveChallengeAsync(returnUrl, EveAuthenticationCookieDefaults.DefaultExternalCookieAuthenticationScheme);
        }

        private static Task InitEveChallengeAsync(this HttpContext context, string? returnUrl, string scheme)
        { 
            return context.InitEveChallengeAsync(returnUrl, scheme, CreateChallengeAuthenticationProperties(returnUrl, scheme));
        }

        private static Task InitEveChallengeAsync(this HttpContext context, string? returnUrl, string scheme, AuthenticationProperties properties)
        { 
            return context.ChallengeAsync(scheme, properties);
        }

        private static ChallengeResult EveChallenge(this HttpContext context, string? returnUrl, string scheme)
        {
            return new ChallengeResult(scheme, CreateChallengeAuthenticationProperties(returnUrl, scheme));
        }

        private static AuthenticationProperties CreateChallengeAuthenticationProperties(string? returnUrl, string scheme)
        { 
            return new AuthenticationProperties
            {
                RedirectUri = EveConstants.PostOAuthCallbackPath,
                Items =
                {
                    { "returnUrl", returnUrl },
                    { "scheme", scheme },
                }
            };
        }
    }
}
