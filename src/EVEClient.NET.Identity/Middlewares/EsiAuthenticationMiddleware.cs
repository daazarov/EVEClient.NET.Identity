using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.Services;
using EVEClient.NET.Identity.Stores;

namespace EVEClient.NET.Identity
{
    internal class EsiAuthenticationMiddleware
    {
        private readonly RequestDelegate _next;

        /// <summary>
        /// Initializes a new instance of <see cref="EsiAuthenticationMiddleware"/>.
        /// </summary>
        /// <param name="next">The next item in the middleware pipeline.</param>
        public EsiAuthenticationMiddleware(RequestDelegate next)
        {
            ArgumentNullException.ThrowIfNull(next);

            _next = next;
        }

        public async Task Invoke(
            HttpContext context,
            IUserSession userSession,
            IAccessTokenStore accessTokenStore,
            IRefreshTokenStore refreshTokenStore,
            ITokenHandlerProvider tokenHandlerProvider)
        {
            ArgumentNullException.ThrowIfNull(context);

            context.Response.OnStarting(async () =>
            {
                if (context.SignOutCalled())
                {
                    // Сlear user token data and revoke tokens on the ESI SSO side
                    // We can still retrieve the session data even after the HttpContext.SignOutAsync method call,
                    // since it's still the same scoped request and the authentication cookies have not been deleted yet.
                    if (context.User.GetEveIdentity()?.IsAuthenticated == true)
                    {
                        var refreshToken = await context.GetEveRefreshTokenAsync();
                        var sessionId = await userSession.GetCurrentSessionIdAsync();

                        if (refreshToken.IsPresent())
                        {
                            // there's no point in initializing of handler, we just want to send a revoke request
                            var handler = await tokenHandlerProvider.GetRefreshTokenHandler(context, await context.GetEveCookieAuthenticationSchemeName(), initialize: false);
                            if (handler != null)
                            {
                                await handler.RevokeToken(refreshToken);
                            }
                        }

                        if (sessionId.IsPresent())
                        {
                            await accessTokenStore.RemoveAccessTokenAsync(sessionId: sessionId);
                            await refreshTokenStore.RemoveRefreshTokenAsync(sessionId: sessionId);
                        }
                    }
                }
            });

            if (context.IsPrimaryIdentityEnable() &&
                context.User.Identity.IsEveIdentity() &&
                context.User.Identity.IsAuthenticated)
            {
                // Do nothing. Probably AspNetCore AuthenticationMiddleware has already authenticated the user using EVE AuthenticationScheme as default.
            }
            else
            {
                var result = await context.AuthenticateAsync(await context.GetEveCookieAuthenticationSchemeName());
                if (result.Succeeded)
                {
                    if (context.IsPrimaryIdentityEnable())
                    {
                        context.User = result.Principal;
                    }
                    else
                    {
                        context.User.AddIdentity(result.Principal.Identities.First());
                    }
                }
            }

            await _next(context);
        }
    }
}
