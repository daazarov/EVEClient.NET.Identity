using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Extensions;

namespace EVEClient.NET.Identity.Services
{
    public class DefaultEveRefreshTokenCookieHandler : BaseEveRefreshTokenHandler
    {
        public DefaultEveRefreshTokenCookieHandler(ILogger<DefaultEveRefreshTokenCookieHandler> logger, IOptionsMonitor<EveAuthenticationOAuthOptions> options)
            : base(logger, options)
        {
        }

        protected override Task<RefreshTokenResult> HandleRequestTokenAsync()
        {
            var refreshToken = AuthenticationProperties!.GetTokenValue(OAuthConstants.TokenTypes.RefreshToken);

            return refreshToken.IsPresent()
                ? Task.FromResult(RefreshTokenResult.Success(refreshToken))
                : Task.FromResult(RefreshTokenResult.Empty());
        }
    }
}
