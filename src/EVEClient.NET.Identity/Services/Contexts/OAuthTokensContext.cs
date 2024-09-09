using System.IdentityModel.Tokens.Jwt;

using Microsoft.AspNetCore.Authentication;

namespace EVEClient.NET.Identity.Services
{
    public class OAuthTokensContext
    {
        /// <summary>
        /// Gets the access token issued by the OAuth provider.
        /// </summary>
        public string AccessToken { get; }

        /// <summary>
        /// Gets the token type.
        /// </summary>
        /// <remarks>
        /// Typically the string “bearer”.
        /// </remarks>
        public string TokenType { get; }

        /// <summary>
        /// Gets a refresh token that applications can use to obtain another access token if tokens can expire.
        /// </summary>
        public string RefreshToken { get; }

        /// <summary>
        /// Gets the creation date.
        /// </summary>
        public DateTimeOffset IssuedAt { get; }

        /// <summary>
        /// Gets the validatity lifetime of the token.
        /// </summary>
        public DateTimeOffset ExpiresAt { get; }

        /// <summary>
        /// Gets esi scopes associated with access token.
        /// </summary>
        public IReadOnlyCollection<string> Scopes { get; }

        public OAuthTokensContext(IEnumerable<AuthenticationToken> tokens)
        {
            AccessToken = tokens.First(x => x.Name.Equals("access_token", StringComparison.OrdinalIgnoreCase)).Value;
            RefreshToken = tokens.First(x => x.Name.Equals("refresh_token", StringComparison.OrdinalIgnoreCase)).Value;
            TokenType = tokens.First(x => x.Name.Equals("token_type", StringComparison.OrdinalIgnoreCase)).Value;
            ExpiresAt = DateTimeOffset.Parse(tokens.First(x => x.Name.Equals("expires_at", StringComparison.OrdinalIgnoreCase)).Value);
            IssuedAt = DateTimeOffset.Parse(tokens.First(x => x.Name.Equals("issued_at", StringComparison.OrdinalIgnoreCase)).Value);

            var jwtSecurityToken = new JwtSecurityTokenHandler().ReadJwtToken(AccessToken);

            Scopes = new List<string>
                (jwtSecurityToken.Claims
                    .Where(x => x.Type.Equals(EveClaims.Issuers.Scope, StringComparison.OrdinalIgnoreCase))
                    .Select(claim => claim.Value)
                );
        }
    }
}
