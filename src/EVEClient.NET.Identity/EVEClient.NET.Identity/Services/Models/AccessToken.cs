namespace EVEClient.NET.Identity.Services
{
    public class AccessToken
    {
        /// <summary>
        /// Gets or sets the list of granted scopes for the token.
        /// </summary>
        public IReadOnlyList<string> GrantedScopes { get; set; } = default!;

        /// <summary>
        /// Gets the expiration time of the token.
        /// </summary>
        public DateTimeOffset Expires { get; set; }

        /// <summary>
        /// Gets the serialized representation of the token.
        /// </summary>
        public string Value { get; set; } = default!;
    }
}
