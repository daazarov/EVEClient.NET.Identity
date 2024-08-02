using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace EVEClient.NET.Identity.Services
{
    public class ClaimsIdentityContext : SignInBehaviorContext
    {
        /// <summary>
        /// Gets the created claims identity.
        /// </summary>
        public ClaimsIdentity Identity { get; }
        
        public ClaimsIdentityContext(SignInBehaviorContext existing, ClaimsIdentity identity) : base(existing)
        {
            ArgumentNullException.ThrowIfNull(identity);

            Identity = identity;
        }
    }
}
