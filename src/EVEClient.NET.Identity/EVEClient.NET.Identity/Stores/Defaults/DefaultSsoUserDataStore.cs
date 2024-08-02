using EVEClient.NET.Extensions;
using EVEClient.NET.Identity.Extensions;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace EVEClient.NET.Identity.Stores
{
    public class DefaultSsoUserDataStore<T>
    {
        private const string StorePrefix = "EveSsoUserData";

        protected readonly IUserDataStore Store;

        protected readonly ILogger<DefaultSsoUserDataStore<T>> Logger;

        protected string DataType;

        protected DefaultSsoUserDataStore(IUserDataStore store, ILogger<DefaultSsoUserDataStore<T>> logger, string dataType)
        {
            ArgumentNullException.ThrowIfNull(store);
            ArgumentNullException.ThrowIfNull(logger);

            if (dataType.IsMissing())
            {
                throw new ArgumentNullException(nameof(dataType));
            }

            Store = store;
            Logger = logger;
            DataType = dataType;
        }

        protected virtual Task<string> StoreItemAsync(T item, string sessionId, string subjectId, DateTimeOffset creationDate, DateTimeOffset? expiration)
        {
            var key = GenerateKey(sessionId, subjectId);

            return StoreItemAsync(key, item, sessionId, subjectId, creationDate, expiration);
        }

        protected virtual async Task<string> StoreItemAsync(string key, T item, string sessionId, string subjectId, DateTimeOffset creationDate, DateTimeOffset? expiration)
        {
            var serializedItem = JsonConvert.SerializeObject(item);

            var userData = new EveUserData
            {
                Key = key,
                Data = serializedItem,
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
                    return JsonConvert.DeserializeObject<T>(userData.Data);
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
            return (StorePrefix + ":" + subjectId + ":" + sessionId + ":" + DataType).SHA256();
        }
    }
}
