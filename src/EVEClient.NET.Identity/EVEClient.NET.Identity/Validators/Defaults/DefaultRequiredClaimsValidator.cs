using System.Security.Claims;

namespace EVEClient.NET.Identity.Validators
{
    public class DefaultRequiredClaimsValidator : IRequiredClaimsValidator
    {
        public RequiredClaimsValidationResult Validate(IEnumerable<Claim> claims)
        {
            var missingClaims = new List<string>();

            foreach (var requiredClaimType in EveConstants.RequiredClaimNames)
            {
                if (claims.FirstOrDefault(x => x.Type == requiredClaimType) == null)
                {
                    missingClaims.Add(requiredClaimType);
                }
            }

            if (missingClaims.Any())
            {
                return RequiredClaimsValidationResult.Failed($"Missing the following required claims: {string.Join(", ", missingClaims)}", missingClaims);
            }

            return RequiredClaimsValidationResult.Success();
        }
    }
}
