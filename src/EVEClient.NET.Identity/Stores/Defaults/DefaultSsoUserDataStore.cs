using System.Text.Json;

using Microsoft.Extensions.Logging;

using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Extensions;

namespace EVEClient.NET.Identity.Stores
{
    public class DefaultSsoUserDataStore<T>
    {
        /// <summary>
        /// Gets the <see cref="IUserDataStore"/>.
        /// </summary>
        protected IUserDataStore Store { get; }

        /// <summary>
        /// Gets the <see cref="ILogger"/>.
        /// </summary>
        protected ILogger<DefaultSsoUserDataStore<T>> Logger { get; }

        /// <summary>
        /// Gets the <see cref="IStorageKeyGenerator"/>.
        /// </summary>
        protected IStorageKeyGenerator KeyGenerator { get; }

        /// <summary>
        /// Gets the data type of the storage.
        /// </summary>
        protected string DataType { get; }

        private const string Separator = ":";

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
            var randomKey = KeyGenerator.GenerateKey();

            return string.Join(Separator, randomKey, subjectId, sessionId, DataType).SHA256();
        }
    }
}
