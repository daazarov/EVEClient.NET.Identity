using System.Text.Json;

using Microsoft.Extensions.Logging;

using EVEClient.NET.Identity.Extensions;

namespace EVEClient.NET.Identity.Stores
{
    public class DefaultSsoUserDataStore<T>
    {
        protected readonly IUserDataStore Store;

        protected readonly ILogger<DefaultSsoUserDataStore<T>> Logger;

        protected readonly IStorageKeyGenerator KeyGenerator;

        protected string DataType;

        protected DefaultSsoUserDataStore(IUserDataStore store, ILogger<DefaultSsoUserDataStore<T>> logger, IStorageKeyGenerator keyGenerator, string dataType)
        {
            ArgumentNullException.ThrowIfNull(store);
            ArgumentNullException.ThrowIfNull(logger);

            if (dataType.IsMissing())
            {
                throw new ArgumentNullException(nameof(dataType));
            }

            Store = store;
            Logger = logger;
            KeyGenerator = keyGenerator;
            DataType = dataType;
        }

        protected virtual Task<string> StoreItemAsync(T item, string sessionId, string subjectId, DateTimeOffset creationDate, DateTimeOffset? expiration)
        {
            var key = GenerateKey(sessionId, subjectId);

            return StoreItemAsync(key, item, sessionId, subjectId, creationDate, expiration);
        }

        protected virtual async Task<string> StoreItemAsync(string key, T item, string sessionId, string subjectId, DateTimeOffset creationDate, DateTimeOffset? expiration)
        {
            var userData = new EveUserData
            {
                Key = key,
                Data = JsonSerializer.Serialize(item),
                Expiration = expiration,
                SessionId = sessionId,
                SubjectId = subjectId,
                CreationTime = creationDate,
                Type = DataType
            };

            await Store.StoreAsync(userData);

            return key;
        }

        protected virtual async Task<T?> GetItemAsync(string key)
        {
            var userData = await Store.GetAsync(key);

            if (userData is not null && userData.Type == DataType)
            {
                try
                {
                    return JsonSerializer.Deserialize<T>(userData.Data);
                }
                catch (Exception ex)
                {
                    Logger.LogWarning(ex, "Failed to deserialize data from IUserDataStore. {Key}, {DataType}", key, DataType);
                }
            }

            return default;
        }

        protected virtual Task RemoveItemAsync(string key)
        {
            return Store.RemoveAsync(key);
        }

        protected virtual string GenerateKey(string sessionId, string subjectId)
        {
            return KeyGenerator.GenerateKey(sessionId, subjectId, DataType);
        }
    }
}
