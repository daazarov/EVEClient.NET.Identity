namespace EVEClient.NET.Identity.Stores
{
    public interface IRefreshTokenStore
    {
        /// <summary>
        /// Returns the <see cref="RefreshTokenData"/> if found.
        /// </summary>
        /// <param name="key">The refresh token reference key.</param>
        Task<RefreshTokenData?> GetRefreshTokenAsync(string key);

        /// <summary>
        /// Remove refresh token records from storage by key.
        /// </summary>
        /// <param name="key">The storage key.</param>
        /// <returns>The <see cref="Task"/>.</returns>
        Task RemoveRefreshTokenAsync(string key);

        /// <summary>
        /// Remove refresh token records from storage by filter.
        /// </summary>
        /// <param name="subjectId">The subject id.</param>
        /// <param name="sessionId">The session id.</param>
        /// <returns>The <see cref="Task"/>.</returns>
        Task RemoveRefreshTokenAsync(string? subjectId = null, string? sessionId = null);

        /// <summary>
        /// Store refresh token data in a storage.
        /// </summary>
        /// <param name="token">The <see cref="AccessTokenData"/>.</param>
        /// <returns>The key that can be used to retrieve the data later.</returns>
        Task<string> StoreRefreshTokenAsync(RefreshTokenData token);

        /// <summary>
        /// Update the <see cref="RefreshTokenData"/> in the storage. Create if not exists.
        /// </summary>
        /// <param name="key">The storage key.</param>
        /// <param name="token">The updated <see cref="AccessTokenData"/>.</param>
        /// <returns>The <see cref="Task"/>.</returns>
        Task UpdateRefreshTokenAsync(string key, RefreshTokenData token);
    }
}
