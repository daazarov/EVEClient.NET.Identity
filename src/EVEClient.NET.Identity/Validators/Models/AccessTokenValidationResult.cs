namespace EVEClient.NET.Identity.Validators
{
    public class AccessTokenValidationResult : ValidationResult
    {
        public Exception? Exception { get; private set; }

        public static AccessTokenValidationResult Success() => new AccessTokenValidationResult { Succeeded = true };

        public static AccessTokenValidationResult Failed(string error) => new AccessTokenValidationResult { Error = error };

        public static AccessTokenValidationResult Failed(Exception exception) => new AccessTokenValidationResult { Exception = exception, Error = exception.Message };
    }
}
