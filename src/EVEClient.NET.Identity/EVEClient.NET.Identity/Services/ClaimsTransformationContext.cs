using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;

namespace EVEClient.NET.Identity.Services
{
    public class ClaimsTransformationContext
    {
        /// <summary>
        /// Gets the claims collection for modification with already prepared claims.
        /// </summary>
        public ICollection<Claim> IssuedClaims { get; }

        /// <summary>
        /// Gets the issuer that should be used when any claims are issued.
        /// </summary>
        /// <value>
        /// The <c>ClaimsIssuer</c> configured in <see cref="EVEAuthenticationOAuthOptions"/>, if configured.
        /// </value>
        public string? ClaimsIssuer { get; }

        /// <summary>
        /// Gets the <see cref="AuthenticationToken"/> collection that was extracted from <see cref="OAuthTokenResponse"/>
        /// </summary>
        public IReadOnlyCollection<AuthenticationToken> OAuthTokens { get; }

        /// <summary>
        /// Gets the original <see cref="Claim"/> collection which was obtained from EVE SSO access token.
        /// </summary>
        public IReadOnlyCollection<Claim> OAuthClaims { get; }


        public ClaimsTransformationContext(
            ICollection<Claim> issuedClaims,
            string? claimsIssuer,
            IReadOnlyCollection<AuthenticationToken> oauthTokens,
            IReadOnlyCollection<Claim> oauthClaims)
        {
            ArgumentNullException.ThrowIfNull(issuedClaims);
            ArgumentNullException.ThrowIfNull(oauthTokens);
            ArgumentNullException.ThrowIfNull(oauthClaims);

            IssuedClaims = issuedClaims;
            ClaimsIssuer = claimsIssuer;
            OAuthTokens = oauthTokens;
            OAuthClaims = oauthClaims;
        }
    }
}
