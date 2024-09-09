using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace EVEClient.NET.Identity.Services
{
    /// <summary>
    /// Created per request to handle token request for a particular authenticated user.
    /// </summary>
    /// <typeparam name="TResult">Class describing the result of token request.</typeparam>
    public interface ITokenHandler<TResult> where TResult : class
    {
        /// <summary>
        /// Gets the authentication scheme name.
        /// </summary>
        /// <remarks>Configured during creation via <see cref="ITokenHandlerProvider"/>.</remarks>
        string Scheme { get; protected internal set; }
        
        /// <summary>
        /// Returns the result of token request
        /// </summary>
        /// <returns>The <see cref="Task"/>.</returns>
        Task<TResult> RequestTokenAsync();

        /// <summary>
        /// Initialize the context of handler. The handler should initialize anything it needs from the request as part of this method.
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <param name="principal">The <see cref="ClaimsPrincipal"/>.</param>
        /// <param name="properties">The <see cref="AuthenticationProperties"/>.</param>
        /// <returns>The <see cref="Task"/>.</returns>
        Task InitializeAsync(HttpContext context, ClaimsPrincipal? principal, AuthenticationProperties? properties);
    }
}
