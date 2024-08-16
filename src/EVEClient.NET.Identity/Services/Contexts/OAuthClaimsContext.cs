using System.Security.Claims;

using EVEClient.NET.Identity.Extensions;

namespace EVEClient.NET.Identity.Services
{
    public class OAuthClaimsContext : SignInBehaviorContext
    {
        /// <summary>
        /// Gets the extracted claims from EVE SSO access token.
        /// </summary>
        public IReadOnlyCollection<Claim> OAuthClaims { get; }

        public OAuthClaimsContext(SignInBehaviorContext context, Claim[] oauthClaims) : base(context)
        {
            if (oauthClaims.IsMissing())
            {
                throw new ArgumentNullException(nameof(oauthClaims));
            }

            OAuthClaims = oauthClaims;
        }
    }
}
