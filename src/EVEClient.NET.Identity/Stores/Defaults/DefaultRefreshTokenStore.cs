using Microsoft.Extensions.Logging;

namespace EVEClient.NET.Identity.Stores
{
    public class DefaultRefreshTokenStore : DefaultSsoUserDataStore<RefreshTokenData>, IRefreshTokenStore
    {
        public DefaultRefreshTokenStore(IUserDataStore store, ILogger<DefaultRefreshTokenStore> logger, IStorageKeyGenerator keyGenerator)
            : base(store, logger, keyGenerator, "refresh_token")
        {
        }

        public Task<RefreshTokenData?> GetRefreshTokenAsync(string key)
        {
            return GetItemAsync(key);
        }

        public Task RemoveRefreshTokenAsync(string key)
        {
            return RemoveItemAsync(key);
        }

        public Task RemoveRefreshTokenAsync(string? subjectId = null, string? sessionId = null)
        {
            return Store.RemoveAsync(new EveUserDataFilter { DataType = DataType, SubjectId = subjectId, SessionId = sessionId });
        }

        public Task<string> StoreRefreshTokenAsync(RefreshTokenData token)
        {
            return StoreItemAsync(token, token.SessionId, token.SubjectId.ToString(), token.CreationTime, null);
        }

        public Task UpdateRefreshTokenAsync(string key, RefreshTokenData token)
        {
            return StoreItemAsync(key, token, token.SessionId, token.SubjectId.ToString(), token.CreationTime, null);
        }
    }
}
