using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace EVEClient.NET.Identity.Services
{
    public interface IPostOAuthBehavior
    {
        /// <summary>
        /// Invoke the behavior.
        /// </summary>
        /// <returns>The <see cref="Task"/>.</returns>
        Task Invoke();

        /// <summary>
        /// Initialize the context of behavior.
        /// </summary>
        /// <param name="authenticateResult">The <see cref="AuthenticateResult"/>.</param>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <returns>The <see cref="Task"/>.</returns>
        Task InitializeAsync(AuthenticateResult authenticateResult, HttpContext context);
    }
}
