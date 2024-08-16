using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;

namespace EVEClient.NET.Identity.Configuration
{
    public class EveRenewAccessTokenFailureContext
    {
        public Exception? Failure { get; init; } 

        public OAuthTokenResponse? OAuthTokenResponse { get; init; }

        public RenewAccessTokenFailureReason Reason { get; init; } = RenewAccessTokenFailureReason.Unknown;

        public required HttpContext HttpContext { get; init; }

        public string? SubjectId { get; init; }
    }

    public enum RenewAccessTokenFailureReason
    { 
        Unknown,
        OAuthResponseFailed,
        MissingRefreshTokenInStorage,
        MissingAccessTokenInOAuthResponse,
        MissingRefreshTokenInOAuthResponse,
        MissingExpiresInOAuthResponse,
        UserNotAuthenticated,
        AccessTokenValidationFailed
    }
}
