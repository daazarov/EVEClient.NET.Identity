using System.Collections.Concurrent;

using EVEClient.NET.Identity.Extensions;

namespace EVEClient.NET.Identity.Stores
{
    internal class DefaultInMemoryUserDataStore : IUserDataStore
    {
        private static readonly ConcurrentDictionary<string, EveUserData> _store = [];

        public virtual Task<EveUserData?> GetAsync(string key)
        {
            if (_store.TryGetValue(key, out var token))
            {
                return Task.FromResult<EveUserData?>(token);
            }

            return Task.FromResult<EveUserData?>(null);
        }

        public virtual Task RemoveAsync(string key)
        {
            _store.TryRemove(key, out _);

            return Task.CompletedTask;
        }

        public virtual async Task RemoveAsync(EveUserDataFilter filter)
        {
            ArgumentNullException.ThrowIfNull(filter);

            if (filter.DataType.IsMissing())
            {
                throw new InvalidOperationException("DataType in the EveUserDataFilter can not be null or empty.");
            }

            var items = _store.Select(x => x.Value).Where(x => x.Type == filter.DataType);

            if (filter.SubjectId.IsPresent() && filter.SessionId.IsMissing())
            {
                items = items.Where(x => x.SubjectId.Equals(filter.SubjectId));
            }
            else if (filter.SubjectId.IsMissing() && filter.SessionId.IsPresent())
            {
                items = items.Where(x => x.SessionId.Equals(filter.SessionId));
            }
            else if (filter.SubjectId.IsPresent() && filter.SessionId.IsPresent())
            {
                items = items.Where(x => x.SessionId.Equals(filter.SessionId) && x.SubjectId.Equals(filter.SubjectId));
            }
            else
            {
                throw new InvalidOperationException("EveUserDataFilter can not be empty. You need to specify session id and/or subject id.");
            }

            foreach (var item in items)
            {
                await RemoveAsync(item.Key);
            }
        }

        public virtual Task StoreAsync(EveUserData data)
        {
            _store[data.Key] = data;

            return Task.CompletedTask;
        }
    }
}
