using System.Diagnostics.CodeAnalysis;

namespace EVEClient.NET.Identity.Services
{
    public abstract class TokenResult<T>
    {
        private readonly T? _token;
        private readonly bool _success;

        public Exception? Error { get; protected set; }

        public string? ErrorMessage { get; protected set; }

        // <summary>
        /// Initializes a new instance of <see cref="TokenResult{T}"/>.
        /// </summary>
        /// <param name="token">The <see cref="AccessToken"/> in case it was successful.</param>
        protected TokenResult(T? token)
        {
            if (token != null)
            {
                _token = token;
                _success = true;
            }
        }

        /// <summary>
        /// Determines whether the token request was successful and makes the token available for use when it is.
        /// </summary>
        /// <param name="token">The <see cref="T"/> if the request was successful.</param>
        /// <returns><c>true</c> when the token request is successful; <c>false</c> otherwise.</returns>
        public bool TryGetToken([NotNullWhen(true)] out T? token)
        {
            if (_success)
            {
                token = _token!;
                return true;
            }
            else
            {
                token = default(T);
                return false;
            }
        }
    }
}
