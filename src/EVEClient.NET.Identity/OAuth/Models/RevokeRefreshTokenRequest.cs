using EVEClient.NET.Identity.Extensions;

namespace EVEClient.NET.Identity.OAuth
{
    public class RevokeRefreshTokenRequest : OAuthRequest
    {
        /// <summary>
        /// Gets or sets the refresh token value.
        /// </summary>
        public string RefreshToken { get; set; } = default!;

        protected override void Validate()
        {
            base.Validate();

            if (RefreshToken.IsMissing())
                throw new ArgumentNullException(nameof(RefreshToken));
        }
    }
}
