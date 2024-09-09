namespace EVEClient.NET.Identity.Services
{
    public interface IStoreTokenHandler<TInput> where TInput : class
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="token">An object describing the token.</param>
        /// <returns>The <see cref="Task"/>.</returns>
        Task<bool> StoreTokensAsync(TInput token);
    }
}
