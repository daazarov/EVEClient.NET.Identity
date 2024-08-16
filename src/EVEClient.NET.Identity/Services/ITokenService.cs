namespace EVEClient.NET.Identity.Services
{
    public interface ITokenService
    {
        /// <summary>
        /// Tries to revoke token on the EVE SSO server side.
        /// </summary>
        /// <param name="tokenType">The type of token.</param>
        /// <remarks>only "access_token" and "refresh_token" are accepted as the value of the input parameter</remarks>
        Task RevokeRemoteToken(string tokenType);

        /// <summary>
        /// Tries to get an access token for the current user.
        /// </summary>
        /// <returns>A <see cref="Task{AccessTokenResult}"/> that will contain the <see cref="AccessTokenResult"/> when completed.</returns>
        Task<AccessTokenResult> RequestAccessToken();
    }
}
