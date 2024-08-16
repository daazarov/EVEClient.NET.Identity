namespace EVEClient.NET.Identity.Stores
{
    public class RefreshTokenData
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
        /// Gets the refresh token value.
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
    }
}
