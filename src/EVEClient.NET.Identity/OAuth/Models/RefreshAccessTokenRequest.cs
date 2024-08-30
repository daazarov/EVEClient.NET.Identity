namespace EVEClient.NET.Identity.OAuth
{
    public class RefreshAccessTokenRequest : OAuthRequest
    {
        /// <summary>
        /// Gets or sets refresh token value.
        /// </summary>
        public string RefreshToken { get; set; } = default!;

        /// <summary>
        /// Gets or sets space separated list of the requested scopes.
        /// </summary>
        public string[]? Scopes { get; set; }
    }
}
