using System.Diagnostics.CodeAnalysis;

namespace EVEClient.NET.Identity.Services
{
    public class AccessTokenResult
    {
        private readonly AccessToken? _token;
        private readonly bool _success;

        public Exception? Error { get; private set; }

        public string? ErrorMessage { get; private set; }

        // <summary>
        /// Initializes a new instance of <see cref="AccessTokenResult"/>.
        /// </summary>
        /// <param name="token">The <see cref="AccessToken"/> in case it was successful.</param>
        private AccessTokenResult(AccessToken? token)
        {
            if (token != null)
            {
                _token = token;
                _success = true;
            }
        }

        public static AccessTokenResult Success(AccessToken token) => new AccessTokenResult(token ?? throw new ArgumentNullException(nameof(token)));

        public static AccessTokenResult Failure(string message, Exception? error = null) => new AccessTokenResult(null) { ErrorMessage = message, Error = error };

        /// <summary>
        /// Determines whether the token request was successful and makes the <see cref="AccessToken"/> available for use when it is.
        /// </summary>
        /// <param name="accessToken">The <see cref="AccessToken"/> if the request was successful.</param>
        /// <returns><c>true</c> when the token request is successful; <c>false</c> otherwise.</returns>
        public bool TryGetToken([NotNullWhen(true)] out AccessToken? accessToken)
        {
            if (_success)
            {
                accessToken = _token!;
                return true;
            }
            else
            {
                accessToken = null;
                return false;
            }
        }
    }
}
