namespace EVEClient.NET.Identity.Stores
{
    public interface IRefreshTokenStore
    {
        Task<RefreshTokenData?> GetRefreshTokenAsync(string key);

        Task RemoveRefreshTokenAsync(string key);

        Task RemoveRefreshTokenAsync(string? subjectId = null, string? sessionId = null);

        Task<string> StoreRefreshTokenAsync(RefreshTokenData token);

        Task UpdateRefreshTokenAsync(string key, RefreshTokenData token);
    }
}
