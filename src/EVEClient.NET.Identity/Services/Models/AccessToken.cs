namespace EVEClient.NET.Identity.Services
{
    public class AccessToken
    {
        /// <summary>
        /// Gets or sets the list of granted scopes for the token.
        /// </summary>
        public IReadOnlyList<string> GrantedScopes { get; init; } = new List<string>();

        /// <summary>
        /// Gets the expiration time of the token.
        /// </summary>
        public required DateTimeOffset Expires { get; init; }

        /// <summary>
        /// Gets the serialized representation of the token.
        /// </summary>
        public required string Value { get; init; }
    }
}
