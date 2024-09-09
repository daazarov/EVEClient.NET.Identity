using Microsoft.AspNetCore.Http;

namespace EVEClient.NET.Identity.Services
{
    public interface ITokenHandlerProvider
    {
        /// <summary>
        /// Creates or returns the <see cref="IAccessTokenHandler"/> from the per-request cache.
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <param name="authenticationScheme">The authentication scheme name.</param>
        /// <returns>The <see cref="IAccessTokenHandler"/>.</returns>
        Task<IAccessTokenHandler?> GetAccessTokenHandler(HttpContext context, string authenticationScheme);

        /// <summary>
        /// Creates or returns the <see cref="IRefreshTokenHandler"/> from the per-request cache.
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <param name="authenticationScheme">The authentication scheme name.</param>
        /// <returns>The <see cref="IRefreshTokenHandler"/>.</returns>
        Task<IRefreshTokenHandler?> GetRefreshTokenHandler(HttpContext context, string authenticationScheme);
    }
}
