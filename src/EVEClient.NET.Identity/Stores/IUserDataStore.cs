namespace EVEClient.NET.Identity.Stores
{
    public interface IUserDataStore
    {
        /// <summary>
        /// Returns the <see cref="EveUserData"/> if found by key.
        /// </summary>
        /// <param name="key">The storage key.</param>
        /// <returns>The <see cref="EveUserData"/> instance.</returns>
        Task<EveUserData?> GetAsync(string key);

        /// <summary>
        /// Remove user data record from storage by key.
        /// </summary>
        /// <param name="key">The storage key.</param>
        /// <returns>The <see cref="Task"/>.</returns>
        Task RemoveAsync(string key);

        /// <summary>
        /// Remove user data records from storage by filter.
        /// </summary>
        /// <param name="filter"></param>
        /// <returns>The <see cref="Task"/>.</returns>
        Task RemoveAsync(EveUserDataFilter filter);

        /// <summary>
        /// Store the <see cref="EveUserData"/> in a storage.
        /// </summary>
        /// <param name="data"></param>
        /// <returns>The <see cref="Task"/>.</returns>
        Task StoreAsync(EveUserData data);
    }
}
