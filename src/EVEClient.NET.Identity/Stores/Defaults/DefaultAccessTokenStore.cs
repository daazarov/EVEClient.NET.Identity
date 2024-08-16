using Microsoft.Extensions.Logging;

namespace EVEClient.NET.Identity.Stores
{
    public class DefaultAccessTokenStore : DefaultSsoUserDataStore<AccessTokenData>, IAccessTokenStore
    {
        public DefaultAccessTokenStore(IUserDataStore store, ILogger<DefaultAccessTokenStore> logger)
            : base(store, logger, "access_token")
        {
        }

        public Task<AccessTokenData?> GetAccessTokenAsync(string key)
        {
            return GetItemAsync(key);
        }

        public Task RemoveAccessTokenAsync(string key)
        {
            return RemoveItemAsync(key);
        }

        public Task RemoveAccessTokenAsync(string? subjectId = null, string? sessionId = null)
        {
            return Store.RemoveAsync(new EveUserDataFilter { DataType = DataType, SubjectId = subjectId, SessionId = sessionId });
        }

        public Task<string> StoreAccessTokenAsync(AccessTokenData token)
        {
            return StoreItemAsync(token, token.SessionId, token.SubjectId.ToString(), token.CreationTime, token.ExpiresAt);
        }

        public Task UpdateAccessTokenAsync(string key, AccessTokenData token)
        {
            return StoreItemAsync(key, token, token.SessionId, token.SubjectId.ToString(), token.CreationTime, token.ExpiresAt);
        }
    }
}
