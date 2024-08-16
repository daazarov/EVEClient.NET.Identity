namespace EVEClient.NET.Identity.Stores
{
    public class AccessTokenData
    {
        /// <summary>
        /// Gets the subject id (aka EVE character ID).
        /// </summary>
        public string SubjectId { get; set; } = default!;

        /// <summary>
        ///  Get the token type.
        /// </summary>
        public string TokenType { get; set; } = default!;

        /// <summary>
        /// Gets or sets the list of granted scopes for the token.
        /// </summary>
        public IReadOnlyList<string> GrantedScopes { get; set; } = default!;

        /// <summary>
        /// Gets the serialized representation of the token.
        /// </summary>
        public string Value { get; set; } = default!;

        /// <summary>
        /// Get the session id that is linked to this token.
        /// </summary>
        public string SessionId { get; set; } = default!;

        /// <summary>
        /// Gets the creation time of the token.
        /// </summary>
        public DateTimeOffset CreationTime { get; set; }

        /// <summary>
        /// Gets the expiration time of the token.
        /// </summary>
        public DateTimeOffset ExpiresAt { get; set; }
    }
}
