namespace EVEClient.NET.Identity.Stores
{
    public interface IAccessTokenStore
    {
        Task<AccessTokenData?> GetAccessTokenAsync(string key);

        Task RemoveAccessTokenAsync(string key);

        Task RemoveAccessTokenAsync(string? subjectId = null, string? sessionId = null);

        Task<string> StoreAccessTokenAsync(AccessTokenData token);

        Task UpdateAccessTokenAsync(string key, AccessTokenData token);
    }
}
