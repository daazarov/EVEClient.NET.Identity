namespace EVEClient.NET.Identity.Services
{
    public interface IRefreshTokenHandler : ITokenHandler<RefreshTokenResult>
    {
        /// <summary>
        /// Tries to revoke token on the EVE SSO server side.
        /// </summary>
        Task RevokeToken();
    }
}
