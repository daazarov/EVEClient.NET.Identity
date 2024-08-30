using Microsoft.AspNetCore.Http;

namespace EVEClient.NET.Identity.Services
{
    public interface ITokenService
    {
        /// <summary>
        /// Tries to get an access token for the current user.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="scheme"></param>
        /// <returns>A <see cref="Task{AccessTokenResult}"/> that will contain the <see cref="AccessTokenResult"/> when completed.</returns>
        Task<AccessTokenResult> RequestAccessToken(HttpContext context, string authenticationScheme);

        /// <summary>
        /// Tries to get an refresh token for the current user.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="scheme"></param>
        /// <returns>A <see cref="Task{RefreshTokenResult}"/> that will contain the <see cref="RefreshTokenResult"/> when completed.</returns>
        Task<RefreshTokenResult> RequestRefreshToken(HttpContext context, string authenticationScheme);
    }
}
