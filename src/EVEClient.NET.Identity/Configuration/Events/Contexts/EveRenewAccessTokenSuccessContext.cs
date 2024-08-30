using Microsoft.AspNetCore.Http;

namespace EVEClient.NET.Identity.Configuration
{
    public class EveRenewAccessTokenSuccessContext
    {
        /// <summary>
        /// Gets the <see cref="HttpContext"/>.
        /// </summary>
        public required HttpContext HttpContext { get; init; }

        /// <summary>
        /// Gets the renewed access token.
        /// </summary>
        public required string NewAccessToken { get; init; }

        /// <summary>
        /// Gets the old refresh token that was used to refresh the access token.
        /// </summary>
        public required string OldRefreshToken { get; init; }

        /// <summary>
        /// Gets the new refresh token.
        /// </summary>
        /// <remarks>Can stay the same with old refresh token.</remarks>
        public required string NewRefreshToken { get; init; }

        /// <summary>
        /// Gets the normalized subject (an EVE Character ID).
        /// </summary>
        public required string SubjectId { get; init; }

        /// <summary>
        /// Gets the session id associated with current user session.
        /// </summary>
        public required string SessionId { get; init; }

        /// <summary>
        /// Gets the expiration time of access token.
        /// </summary>
        public required DateTimeOffset ExpiresAt { get; init; }
    }
}
