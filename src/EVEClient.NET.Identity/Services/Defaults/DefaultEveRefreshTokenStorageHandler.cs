using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.Stores;

namespace EVEClient.NET.Identity.Services
{
    public class DefaultEveRefreshTokenStorageHandler : BaseEveRefreshTokenHandler
    {
        /// <summary>
        /// Gets the <see cref="IRefreshTokenStore"/>.
        /// </summary>
        protected IRefreshTokenStore RefreshTokenStore { get; }

        public DefaultEveRefreshTokenStorageHandler(
            ILogger<DefaultEveRefreshTokenStorageHandler> logger,
            IOptionsMonitor<EveAuthenticationOAuthOptions> options,
            IRefreshTokenStore refreshTokenStore) : base(logger, options)
        {
            RefreshTokenStore = refreshTokenStore;
        }

        protected override async Task<RefreshTokenResult> HandleRequestTokenAsync()
        {
            var refreshTokenKey = AuthenticationProperties!.GetRefreshTokenStorageKey();
            if (refreshTokenKey.IsMissing())
            {
                throw new InvalidOperationException("Missing refresh token storage key in the AuthenticationProperties.");
            }

            var refreshTokenData = await RefreshTokenStore.GetRefreshTokenAsync(refreshTokenKey);

            return refreshTokenData != null
                ? RefreshTokenResult.Success(refreshTokenData.Value)
                : RefreshTokenResult.Empty();
        }
    }
}
