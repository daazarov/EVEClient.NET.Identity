using Microsoft.AspNetCore.Authentication.OAuth;

namespace EVEClient.NET.Identity.Services
{
    public interface IRemoteTokensHandler
    {

        /// <summary>
        /// Refresh an access token from the remote provider.
        /// </summary>
        /// <param name="refreshToken">The refreh token value.</param>
        /// <returns>The response <see cref="OAuthTokenResponse"/>.</returns>
        Task<OAuthTokenResponse> RenewAccessToken(string refreshToken);

        /// <summary>
        /// Tries to revoke token on the EVE SSO server side.
        /// </summary>
        /// <param name="tokenType">The type of token.</param>
        /// <param name="token">The token value.</param>
        /// <remarks>only "access_token" and "refresh_token" are accepted as the value of the input parameter</remarks>
        Task RevokeRemoteToken(string tokenType, string token);
    }
}
