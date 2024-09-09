using System.Globalization;
using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.Validators;

namespace EVEClient.NET.Identity.Services
{
    public class DefaultEveAccessTokenCookieHandler : BaseEveAccessTokenHandler
    {
        private bool _shouldRefresh;
        
        public DefaultEveAccessTokenCookieHandler(
            IReceivedAccessTokenValidator tokenValidator,
            ITokenHandlerProvider tokenHandlerProvider,
            ILogger<DefaultEveAccessTokenCookieHandler> logger,
            IOptionsMonitor<EveAuthenticationOAuthOptions> options)
            : base(tokenValidator, tokenHandlerProvider, logger, options)
        {
        }

        public override async Task InitializeAsync(HttpContext context, ClaimsPrincipal? principal, AuthenticationProperties? properties)
        {
            await base.InitializeAsync(context, principal, properties);

            HttpContext.Response.OnStarting(FinishResponseAsync);
        }

        protected override Task<AccessTokenResult> HandleRequestTokenAsync()
        {
            var accessToken = AuthenticationProperties!.GetTokenValue("access_token");
            var expiresAtString = AuthenticationProperties!.GetTokenValue("expires_at");

            if (accessToken.IsMissing())
            {
                return Task.FromResult(AccessTokenResult.Empty());
            }

            if (!DateTimeOffset.TryParse(expiresAtString, out var expiresAt))
            {
                throw new InvalidCastException($"Access token expiration time could not be determined. Invalida data: {expiresAtString}.");
            }

            return Task.FromResult(AccessTokenResult.Success(new AccessToken { Value = accessToken, ExpiresAt = expiresAt, GrantedScopes = [.. Options.Scope] }));
        }

        protected override Task<bool> HandleStoreTokensAsync(AccessTokenStoreRequest request)
        {
            // IMPORTANT:
            // We don't set the "_shouldRefresh" here.
            // The main purpose of the method in only storing tokens in the initialized AuthenticationProperties while SignIn flow
            // and only the calling object can know for sure when to call SignInAsync.
            AuthenticationProperties!.StoreTokens(
            [
                new AuthenticationToken { Name = "access_token", Value = request.AccessToken },
                new AuthenticationToken { Name = "refresh_token", Value = request.RefreshToken },
                new AuthenticationToken { Name = "expires_at", Value = request.ExpiresAt.ToString("o", CultureInfo.InvariantCulture) }
            ]);

            return Task.FromResult(true);
        }

        protected override Task HandleSuccessedRefreshToken(string accessToken, string refreshToken, DateTimeOffset expiresAt)
        {
            AuthenticationProperties!.UpdateTokenValue("access_token", accessToken);
            AuthenticationProperties!.UpdateTokenValue("refresh_token", refreshToken);
            AuthenticationProperties!.UpdateTokenValue("expires_at", expiresAt.ToString("o", CultureInfo.InvariantCulture));

            _shouldRefresh = true;

            return Task.CompletedTask;
        }

        private async Task FinishResponseAsync()
        {
            if (_shouldRefresh)
            {
                var currentAuthenticationResult = await HttpContext.AuthenticateAsync(Scheme);

                // update only if we already have a current user authentication.
                if (currentAuthenticationResult.Succeeded &&
                    currentAuthenticationResult.Principal.GetEveSubject() == Principal!.GetEveSubject())
                {
                    await HttpContext.SignInAsync(Scheme, Principal!, AuthenticationProperties!);
                }
            }
        }
    }
}
