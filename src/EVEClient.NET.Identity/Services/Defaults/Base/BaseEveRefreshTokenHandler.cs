using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.OAuth;

namespace EVEClient.NET.Identity.Services
{
    public abstract class BaseEveRefreshTokenHandler : BaseEveTokenHandler<RefreshTokenResult>, IRefreshTokenHandler
    {
        public BaseEveRefreshTokenHandler(ILogger logger, IOptionsMonitor<EveAuthenticationOAuthOptions> options)
            : base(logger, options)
        {
        }

        /// <summary>
        /// Allows derived types to handle requesting of token.
        /// </summary>
        /// <returns>The <see cref="RefreshTokenResult"/> instance.</returns>
        protected abstract Task<RefreshTokenResult> HandleRequestTokenAsync();

        public override Task<RefreshTokenResult> RequestTokenAsync()
        {
            if (!IsAuthenticated)
            {
                return Task.FromResult(RefreshTokenResult.Failed("EVE user is not authenticated or handler is not initialized."));
            }

            return HandleRequestTokenAsync();
        }

        public async Task RevokeToken()
        {
            if (IsAuthenticated)
            {
                var result = await RequestTokenAsync();

                if (result.TryGetToken(out var refreshToken))
                {
                    await HandleRevokeTokenAsync(refreshToken);
                }
            }
        }

        protected virtual async Task HandleRevokeTokenAsync(string refreshToken)
        {
            var request = new RevokeRefreshTokenRequest
            {
                ClientId = Options.ClientId,
                ClientSecret = Options.ClientSecret,
                RequestUri = new Uri(Options.RevokeTokenEndpoint, UriKind.RelativeOrAbsolute),
                RefreshToken = refreshToken,
            };

            using (var response = await Backchannel.RevokeRefreshTokenAsync(request))
            {
                if (!response.IsSuccessed)
                {
                    Logger.LogError("Failed to revoke refresh token. Error: {Error}; Error Description: {Description}", response.Error, response.ErrorDescription);
                }
            }
        }
    }
}
