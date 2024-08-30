namespace EVEClient.NET.Identity.Services
{
    public class AccessTokenResult : TokenResult<AccessToken>
    {
        public AccessTokenResult(AccessToken? token) : base(token)
        {
        }

        public static AccessTokenResult Success(AccessToken token) => new AccessTokenResult(token ?? throw new ArgumentNullException(nameof(token)));

        public static AccessTokenResult Failed(string message, Exception? error = null) => new AccessTokenResult(null) { ErrorMessage = message, Error = error };
    }
}
