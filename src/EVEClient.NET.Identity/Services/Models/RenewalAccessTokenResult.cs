using System.Diagnostics.CodeAnalysis;
using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.Utils;
using EVEClient.NET.Identity.OAuth;
using Microsoft.AspNetCore.Authentication;
using System.Text;
using Microsoft.AspNetCore.Authentication.OAuth;

namespace EVEClient.NET.Identity.Services
{
    public class RenewalAccessTokenResult : IDisposable
    {
        public Exception? Error { get; init; }

        [MemberNotNullWhen(true, nameof(OAuthTokenResponse), nameof(AccessToken), nameof(RefreshToken), nameof(ExpiresIn), nameof(ExpiresAt))]
        public bool Valid
        {
            get => Error == null &&
                   OAuthTokenResponse != null &&
                   AccessToken.IsPresent() &&
                   RefreshToken.IsPresent() &&
                   ExpiresIn.IsPresent();
        }

        public string? AccessToken => OAuthTokenResponse?.AccessToken;

        public string? RefreshToken => OAuthTokenResponse?.RefreshToken;

        public string? ExpiresIn => OAuthTokenResponse?.ExpiresIn;

        public RefreshAccessTokenResponse? OAuthTokenResponse { get; init; }

        public DateTimeOffset? ExpiresAt { get; init; }

        private RenewalAccessTokenResult(RefreshAccessTokenResponse response)
        {
            OAuthTokenResponse = response;

            if (ExpiresIn.IsPresent())
            {
                ExpiresAt = UnixTimeStampConverter.FromExpiresInToExpiresAtDateTime(ExpiresIn);
            }
        }

        private RenewalAccessTokenResult(Exception exception) : this(null!, exception)
        {
        }

        private RenewalAccessTokenResult(RefreshAccessTokenResponse response, Exception exception)
        {
            OAuthTokenResponse = response;
            Error = exception;
        }

        public void Dispose()
        {
            OAuthTokenResponse?.Dispose();
        }

        /// <summary>
        /// Creates a successful <see cref="RenewalAccessTokenResult"/>.
        /// </summary>
        /// <param name="response">The received successfull <see cref="RefreshAccessTokenResponse"/>.</param>
        /// <returns>A <see cref="RenewalAccessTokenResult"/> instance.</returns>
        public static RenewalAccessTokenResult Success(RefreshAccessTokenResponse response)
        {
            return new RenewalAccessTokenResult(response);
        }

        /// <summary>
        /// Creates a failed <see cref="RenewalAccessTokenResult"/>.
        /// </summary>
        /// <param name="response">The OAuthTokenResponse that containce the error.</param>
        /// <returns>A <see cref="RenewalAccessTokenResult"/> instance.</returns>
        public static RenewalAccessTokenResult Failed(RefreshAccessTokenResponse response, Exception? exception = null)
        {
            return new RenewalAccessTokenResult(response, exception ?? GetStandardErrorException(response));
        }

        /// <summary>
        /// Creates a failed <see cref="RenewalAccessTokenResult"/>.
        /// </summary>
        /// <returns>A <see cref="RenewalAccessTokenResult"/> instance.</returns>
        public static RenewalAccessTokenResult Failed(Exception exception)
        {
            return new RenewalAccessTokenResult(exception);
        }

        internal static Exception GetStandardErrorException(RefreshAccessTokenResponse response)
        {
            var result = new StringBuilder("OAuth token endpoint failure: ");

            var error = response.Error.IsPresent() ? response.Error : "Unknown error";
            var errorDescription = response.ErrorDescription.IsPresent() ? response.ErrorDescription : string.Empty;

            result.Append(error);

            if (response.ErrorDescription.IsPresent())
            {
                result.Append("; Description=");
                result.Append(errorDescription);
            }

            var exception = new AuthenticationFailureException(result.ToString());
            exception.Data["error"] = error.ToString();
            exception.Data["error_description"] = errorDescription.ToString();

            return exception;
        }
    }
}
