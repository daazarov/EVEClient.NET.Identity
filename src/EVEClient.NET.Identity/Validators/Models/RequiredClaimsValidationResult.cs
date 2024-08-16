namespace EVEClient.NET.Identity.Validators
{
    public class RequiredClaimsValidationResult : ValidationResult
    {
        public IEnumerable<string>? MissingClaims { get; private set; }

        public static RequiredClaimsValidationResult Success() => new RequiredClaimsValidationResult { Succeeded = true };

        public static RequiredClaimsValidationResult Failed(string error, List<string> missingClaimTypes) => new RequiredClaimsValidationResult { Error = error, MissingClaims = missingClaimTypes };
    }
}
