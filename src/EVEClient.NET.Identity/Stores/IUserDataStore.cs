namespace EVEClient.NET.Identity.Stores
{
    public interface IUserDataStore
    {
        Task<EveUserData?> GetAsync(string key);

        Task RemoveAsync(string key);

        Task RemoveAsync(EveUserDataFilter filter);

        Task StoreAsync(EveUserData data);
    }
}
