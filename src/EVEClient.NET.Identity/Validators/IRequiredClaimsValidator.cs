using System.Security.Claims;

namespace EVEClient.NET.Identity.Validators
{
    public interface IRequiredClaimsValidator
    {
        RequiredClaimsValidationResult Validate(IEnumerable<Claim> claims);
    }
}
