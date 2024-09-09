using System.Diagnostics.CodeAnalysis;
using System.Text;

using Microsoft.AspNetCore.Authentication;

using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.Utils;
using EVEClient.NET.Identity.OAuth;

namespace EVEClient.NET.Identity.Services
{
    public class RefreshAccessTokenResult : IDisposable
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

        private RefreshAccessTokenResult(RefreshAccessTokenResponse response)
        {
            OAuthTokenResponse = response;

            if (ExpiresIn.IsPresent())
            {
                ExpiresAt = UnixTimeStampConverter.FromExpiresInToExpiresAtDateTime(ExpiresIn);
            }
        }

        private RefreshAccessTokenResult(Exception exception) : this(null!, exception)
        {
        }

        private RefreshAccessTokenResult(RefreshAccessTokenResponse response, Exception exception)
        {
            OAuthTokenResponse = response;
            Error = exception;
        }

        public void Dispose()
        {
            OAuthTokenResponse?.Dispose();
        }

        /// <summary>
        /// Creates a successful <see cref="RefreshAccessTokenResult"/>.
        /// </summary>
        /// <param name="response">The received successfull <see cref="RefreshAccessTokenResponse"/>.</param>
        /// <returns>A <see cref="RefreshAccessTokenResult"/> instance.</returns>
        public static RefreshAccessTokenResult Success(RefreshAccessTokenResponse response)
        {
            return new RefreshAccessTokenResult(response);
        }

        /// <summary>
        /// Creates a failed <see cref="RefreshAccessTokenResult"/>.
        /// </summary>
        /// <param name="response">The OAuthTokenResponse that containce the error.</param>
        /// <returns>A <see cref="RefreshAccessTokenResult"/> instance.</returns>
        public static RefreshAccessTokenResult Failed(RefreshAccessTokenResponse response, Exception? exception = null)
        {
            return new RefreshAccessTokenResult(response, exception ?? GetStandardErrorException(response));
        }

        /// <summary>
        /// Creates a failed <see cref="RefreshAccessTokenResult"/>.
        /// </summary>
        /// <returns>A <see cref="RefreshAccessTokenResult"/> instance.</returns>
        public static RefreshAccessTokenResult Failed(Exception exception)
        {
            return new RefreshAccessTokenResult(exception);
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
