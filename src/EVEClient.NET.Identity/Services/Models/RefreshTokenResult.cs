namespace EVEClient.NET.Identity.Services
{
    public class RefreshTokenResult : TokenResult<string>
    {
        internal RefreshTokenResult(string? token) : base(token)
        {
        }

        /// <summary>
        /// Creates a succeeded <see cref="RefreshTokenResult"/>.
        /// </summary>
        /// <param name="token">The refresh token value.</param>
        /// <returns>The <see cref="RefreshTokenResult"/> instance.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static RefreshTokenResult Success(string token) => new RefreshTokenResult(token ?? throw new ArgumentNullException(nameof(token)));

        /// <summary>
        /// Creates a failed <see cref="RefreshTokenResult"/>.
        /// </summary>
        /// <param name="message">The error message.</param>
        /// <param name="error">The <see cref="Exception"/>.</param>
        /// <returns>The <see cref="RefreshTokenResult"/> instance.</returns>
        public static RefreshTokenResult Failed(string message, Exception? error = null) => new RefreshTokenResult(null) { ErrorMessage = message, Error = error };

        /// <summary>
        /// Creates an empty <see cref="RefreshTokenResult"/>.
        /// </summary>
        /// <returns>The <see cref="RefreshTokenResult"/> instance.</returns>
        public static RefreshTokenResult Empty() => Failed("Refresh token not found.");
    }
}
