using Microsoft.AspNetCore.Http;

namespace EVEClient.NET.Identity.Services
{
    public class DefaultTokenService : ITokenService
    {
        private readonly ITokenHandlerProvider _tokenHandlerProvider;

        public DefaultTokenService(ITokenHandlerProvider tokenHandlerProvider)
        {
            _tokenHandlerProvider = tokenHandlerProvider;
        }

        public async Task<RefreshTokenResult> RequestRefreshToken(HttpContext context, string authenticationScheme)
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentNullException.ThrowIfNull(authenticationScheme);

            var tokenHandler = await _tokenHandlerProvider.GetRefreshTokenHandler(context, authenticationScheme);
            if (tokenHandler != null)
            {
                return await tokenHandler.RequestTokenAsync();
            }

            throw new InvalidOperationException($"No refresh token handler is configured to request for the scheme: {authenticationScheme}");
        }

        public async Task<AccessTokenResult> RequestAccessToken(HttpContext context, string authenticationScheme)
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentNullException.ThrowIfNull(authenticationScheme);

            var tokenHandler = await _tokenHandlerProvider.GetAccessTokenHandler(context, authenticationScheme);
            if (tokenHandler != null)
            {
                return await tokenHandler.RequestTokenAsync();
            }

            throw new InvalidOperationException($"No access token handler is configured to request for the scheme: {authenticationScheme}");
        }
    }
}
