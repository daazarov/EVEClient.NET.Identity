using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.OAuth;
using EVEClient.NET.Identity.Stores;

namespace EVEClient.NET.Identity.Services
{
    public class DefaultEveRefreshTokenHandler : DefaultTokenHandler<RefreshTokenResult>, IRefreshTokenHandler
    {
        protected IRefreshTokenStore RefreshTokenStore { get; }

        protected IStorageKeyGenerator StorageKeyGenerator { get; }

        public override bool Authenticated => base.Authenticated && Principal.Identity.IsEveIdentity();

        public DefaultEveRefreshTokenHandler(
            IRefreshTokenStore refreshTokenStore,
            IStorageKeyGenerator storageKeyGenerator,
            ILogger<DefaultEveRefreshTokenHandler> logger,
            IOptionsMonitor<EveAuthenticationOAuthOptions> options) : base(logger, options)
        {
            RefreshTokenStore = refreshTokenStore;
            StorageKeyGenerator = storageKeyGenerator;
        }

        public override async Task<RefreshTokenResult> HandleTokenRequest()
        {
            if (!Authenticated)
            {
                return RefreshTokenResult.Failure("EVE user is not authenticated.");
            }

            var subjectId = Principal.GetEveSubject();
            var sessionId = AuthenticationProperties.GetUserSessionId()!;

            var refreshTokenData = await RefreshTokenStore.GetRefreshTokenAsync(StorageKeyGenerator.GenerateKey(subjectId, sessionId, "refresh_token"));

            return refreshTokenData != null
                ? RefreshTokenResult.Success(refreshTokenData.Value)
                : RefreshTokenResult.Failure("Refresh token not found.");
        }

        public async Task RevokeToken(string token)
        {
            var request = new RevokeRefreshTokenRequest
            {
                ClientId = Options.ClientId,
                ClientSecret = Options.ClientSecret,
                RequestUri = new Uri(Options.RevokeTokenEndpoint, UriKind.RelativeOrAbsolute),
                RefreshToken = token,
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
