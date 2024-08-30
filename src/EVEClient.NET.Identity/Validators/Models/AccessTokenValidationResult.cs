using System.Diagnostics.CodeAnalysis;

namespace EVEClient.NET.Identity.Validators
{
    public class AccessTokenValidationResult : ValidationResult
    {
        [MemberNotNullWhen(false, nameof(Exception))]
        public override bool Succeeded { get; protected set; }

        public Exception? Exception { get; private set; }

        public static AccessTokenValidationResult Success() => new AccessTokenValidationResult { Succeeded = true };

        public static AccessTokenValidationResult Failed(Exception exception) => new AccessTokenValidationResult { Exception = exception, Error = exception.Message };
    }
}
