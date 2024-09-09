namespace EVEClient.NET.Identity.Services
{
    public class AccessTokenStoreRequest
    {
        /// <summary>
        /// Gets the subject id (aka EVE character ID).
        /// </summary>
        public required string SubjectId { get; init; }
        
        /// <summary>
        /// Gets the list of granted scopes for the token.
        /// </summary>
        public IReadOnlyList<string> GrantedScopes { get; init; } = new List<string>();

        /// <summary>
        /// Gets the creation date of the token.
        /// </summary>
        public required DateTimeOffset IssuedAt { get; init; }

        /// <summary>
        /// Gets the expiration time of the token.
        /// </summary>
        public required DateTimeOffset ExpiresAt { get; init; }

        /// <summary>
        /// Gets the serialized representation of the token.
        /// </summary>
        public required string AccessToken { get; init; }

        /// <summary>
        /// Gets the refresh token associated with access token.
        /// </summary>
        public required string RefreshToken { get; init; }
    }
}
