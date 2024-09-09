namespace EVEClient.NET.Identity.Stores
{
    public interface IAccessTokenStore
    {
        /// <summary>
        /// Returns the <see cref="AccessTokenData"/> if found by key.
        /// </summary>
        /// <param name="key">The storage key.</param>
        /// <returns>The <see cref="AccessTokenData"/> instance.</returns>
        Task<AccessTokenData?> GetAccessTokenAsync(string key);

        /// <summary>
        /// Remove access token records from storage by key.
        /// </summary>
        /// <param name="key">The storage key.</param>
        /// <returns>The <see cref="Task"/>.</returns>
        Task RemoveAccessTokenAsync(string key);

        /// <summary>
        /// Remove access token records from storage by filter.
        /// </summary>
        /// <param name="subjectId">The subject id.</param>
        /// <param name="sessionId">The session id.</param>
        /// <returns>The <see cref="Task"/>.</returns>
        Task RemoveAccessTokenAsync(string? subjectId = null, string? sessionId = null);

        /// <summary>
        /// Store access token data in a storage.
        /// </summary>
        /// <param name="token">The <see cref="AccessTokenData"/>.</param>
        /// <returns>The key that can be used to retrieve the data later.</returns>
        Task<string> StoreAccessTokenAsync(AccessTokenData token);

        /// <summary>
        /// Update the <see cref="AccessTokenData"/> in the storage. Create if not exists.
        /// </summary>
        /// <param name="key">The storage key.</param>
        /// <param name="token">The updated <see cref="AccessTokenData"/>.</param>
        /// <returns>The <see cref="Task"/>.</returns>
        Task UpdateAccessTokenAsync(string key, AccessTokenData token);
    }
}
