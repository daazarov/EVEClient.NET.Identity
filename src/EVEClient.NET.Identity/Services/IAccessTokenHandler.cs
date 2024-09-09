namespace EVEClient.NET.Identity.Services
{
    public interface IAccessTokenHandler : ITokenHandler<AccessTokenResult>
    {
        /// <summary>
        /// Sends the OAuth refresh token request to the EVE SSO.
        /// </summary>
        Task<RefreshAccessTokenResult> RefreshAccessToken();
    }
}
