using Microsoft.Extensions.Logging;

namespace EVEClient.NET.Identity.Services
{
    public class DefaultAccessTokenProvider : IAccessTokenProvider
    {
        private readonly ITokenService _tokenService;
        private readonly ILogger<DefaultAccessTokenProvider> _logger;
        
        public DefaultAccessTokenProvider(ITokenService tokenService, ILogger<DefaultAccessTokenProvider> logger)
        { 
            _tokenService = tokenService;
            _logger = logger;
        }

        public async Task<string> RequestAccessToken()
        {
            var tokenResult = await _tokenService.RequestAccessToken();
            if (tokenResult.TryGetToken(out var accessToken))
            { 
                return accessToken.Value;
            }

            _logger.LogWarning(tokenResult.Error, "Failed to request access token. Reason: {reason}", tokenResult.ErrorMessage);

            return string.Empty;

            //throw new InvalidOperationException($"Failed to request access token. Reason: {tokenResult.ErrorMessage}", tokenResult.Error);
        }
    }
}
