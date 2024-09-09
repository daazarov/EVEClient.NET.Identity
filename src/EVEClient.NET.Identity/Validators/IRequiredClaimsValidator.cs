using System.Security.Claims;

namespace EVEClient.NET.Identity.Validators
{
    public interface IRequiredClaimsValidator
    {
        /// <summary>
        /// Verifies that all necessary user claims has been created.
        /// </summary>
        /// <param name="claims">The <see cref="Claim"/> collection.</param>
        /// <returns>The <see cref="RequiredClaimsValidationResult"/> instance.</returns>
        RequiredClaimsValidationResult Validate(IEnumerable<Claim> claims);
    }
}
