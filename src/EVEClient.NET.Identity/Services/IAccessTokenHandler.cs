namespace EVEClient.NET.Identity.Services
{
    public interface IAccessTokenHandler : ITokenHandler<AccessTokenResult>
    {
        /// <summary>
        /// Sends the OAuth refresh token request to the EVE SSO .
        /// </summary>
        /// <param name="refreshToken">The refresh token value.</param>
        Task<RenewalAccessTokenResult> RenewAccessToken(string refreshToken);
    }
}
