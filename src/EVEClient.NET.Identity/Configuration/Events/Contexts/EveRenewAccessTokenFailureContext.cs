using Microsoft.AspNetCore.Http;

using EVEClient.NET.Identity.OAuth;

namespace EVEClient.NET.Identity.Configuration
{
    public class EveRenewAccessTokenFailureContext
    {
        /// <summary>
        /// Gets the exception for the failure if present.
        /// </summary>
        public Exception? Failure { get; init; }

        /// <summary>
        /// Gets the <see cref="RefreshAccessTokenResponse"/>.
        /// </summary>
        public RefreshAccessTokenResponse? OAuthTokenResponse { get; init; }

        /// <summary>
        /// Gets the reason for the failure.
        /// </summary>
        public string Reason { get; init; } = "Unknown";

        /// <summary>
        /// Gets the <see cref="HttpContext"/>.
        /// </summary>
        public required HttpContext HttpContext { get; init; }

        /// <summary>
        /// Gets the normalized subject (an EVE Character ID).
        /// </summary>
        public required string SubjectId { get; init; }
    }
}
