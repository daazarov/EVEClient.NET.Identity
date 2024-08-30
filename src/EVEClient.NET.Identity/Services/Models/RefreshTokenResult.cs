namespace EVEClient.NET.Identity.Services
{
    public class RefreshTokenResult : TokenResult<string>
    {
        public RefreshTokenResult(string? token) : base(token)
        {
        }

        public static RefreshTokenResult Success(string token) => new RefreshTokenResult(token ?? throw new ArgumentNullException(nameof(token)));

        public static RefreshTokenResult Failure(string message, Exception? error = null) => new RefreshTokenResult(null) { ErrorMessage = message, Error = error };
    }
}
