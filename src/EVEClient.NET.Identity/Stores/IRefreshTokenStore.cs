namespace EVEClient.NET.Identity.Stores
{
    public interface IRefreshTokenStore
    {
        /// <summary>
        /// Returns the <see cref="RefreshTokenData"/> if found.
        /// </summary>
        /// <param name="key">The refresh token reference key.</param>
        Task<RefreshTokenData?> GetRefreshTokenAsync(string key);

        Task RemoveRefreshTokenAsync(string key);

        Task RemoveRefreshTokenAsync(string? subjectId = null, string? sessionId = null);

        Task<string> StoreRefreshTokenAsync(RefreshTokenData token);

        Task UpdateRefreshTokenAsync(string key, RefreshTokenData token);
    }
}
