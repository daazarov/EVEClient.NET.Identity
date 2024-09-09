namespace EVEClient.NET.Identity.Services
{
    public class AccessTokenResult : TokenResult<AccessToken>
    {
        internal AccessTokenResult(AccessToken? token) : base(token)
        {
        }

        /// <summary>
        /// Creates a succeeded <see cref="AccessTokenResult"/>.
        /// </summary>
        /// <param name="token">The <see cref="AccessToken"/>.</param>
        /// <returns>The <see cref="AccessTokenResult"/> instance.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static AccessTokenResult Success(AccessToken token) => new AccessTokenResult(token ?? throw new ArgumentNullException(nameof(token)));

        /// <summary>
        /// Creates a failed <see cref="AccessTokenResult"/>.
        /// </summary>
        /// <param name="message">The error message.</param>
        /// <param name="error">The <see cref="Exception"/>.</param>
        /// <returns>The <see cref="AccessTokenResult"/> instance.</returns>
        public static AccessTokenResult Failed(string message, Exception? error = null) => new AccessTokenResult(null) { ErrorMessage = message, Error = error };

        /// <summary>
        /// Creates an empty <see cref="AccessTokenResult"/>.
        /// </summary>
        /// <returns>The <see cref="AccessTokenResult"/> instance.</returns>
        public static AccessTokenResult Empty() => Failed("Access token not found.");
    }
}
