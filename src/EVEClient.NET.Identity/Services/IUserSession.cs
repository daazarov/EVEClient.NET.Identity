using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace EVEClient.NET.Identity.Services
{
    public interface IUserSession
    {
        /// <summary>
        /// Creates a session identifier for the signin context.
        /// </summary>
        /// <param name="principal"></param>
        /// <param name="properties"></param>
        /// <returns>Session ID</returns>
        Task InitializeSessionAsync(ClaimsPrincipal principal, AuthenticationProperties properties);

        /// <summary>
        /// Return new session identifier.
        /// </summary>
        Task<string> GenerateSessionIdAsync();

        /// <summary>
        /// Return session id from AuthenticationProperties.
        /// </summary>
        Task<string?> GetCurrentSessionIdAsync();

        /// <summary>
        /// Return subject id from authenticated ClaimsPrincipal (aka EVE character ID).
        /// </summary>
        Task<string?> GetCurrentSubjectIdAsync();

        // <summary>
        /// Return current authenticated user principal.
        /// </summary>
        Task<ClaimsPrincipal?> GetCurrentUserAsync();
    }
}
