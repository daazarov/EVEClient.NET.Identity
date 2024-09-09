using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;

namespace EVEClient.NET.Identity.Services
{
    public class PostOAuthSingInBehaviorResult : PostOAuthBehaviorResult
    {
        /// <summary>
        /// Gets the created <see cref="Microsoft.AspNetCore.Authentication.AuthenticationProperties"/>.
        /// </summary>
        public AuthenticationProperties? AuthenticationProperties { get; private set; }

        /// <summary>
        /// Gets the created <see cref="ClaimsPrincipal"/>.
        /// </summary>
        public ClaimsPrincipal? Principal { get; private set; }

        [MemberNotNullWhen(true, nameof(AuthenticationProperties), nameof(Principal))]
        public override bool Succeeded => base.Succeeded && AuthenticationProperties != null && Principal != null;

        /// <summary>
        /// Creates a succeeded <see cref="PostOAuthSingInBehaviorResult"/>.
        /// </summary>
        /// <param name="principal">The <see cref="ClaimsPrincipal"/>.</param>
        /// <param name="properties">The <see cref="Microsoft.AspNetCore.Authentication.AuthenticationProperties"/>.</param>
        /// <returns>The <see cref="PostOAuthSingInBehaviorResult"/> instance.</returns>
        public static PostOAuthSingInBehaviorResult Success(ClaimsPrincipal principal, AuthenticationProperties properties)
        {
            return new PostOAuthSingInBehaviorResult { Principal = principal, AuthenticationProperties = properties };
        }

        /// <summary>
        /// Creates an unsucceeded <see cref="PostOAuthSingInBehaviorResult"/>.
        /// </summary>
        /// <param name="exception">The <see cref="Exception"/>.</param>
        /// <param name="properties">The <see cref="Microsoft.AspNetCore.Authentication.AuthenticationProperties"/>.</param>
        /// <returns>The <see cref="PostOAuthSingInBehaviorResult"/> instance.</returns>
        public static PostOAuthSingInBehaviorResult Failed(Exception exception, AuthenticationProperties? properties = null)
        {
            return new PostOAuthSingInBehaviorResult { Error = exception, AuthenticationProperties = properties };
        }
    }
}
