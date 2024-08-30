using System.Security.Claims;

namespace EVEClient.NET.Identity.Extensions
{
    public static class ClaimsPrincipalExtensions
    {
        /// <summary>
        /// Returns the value of the claim with the name <see cref="EveClaims.Issuers.Subject"/>.
        /// </summary>
        /// <param name="principal">The <see cref="ClaimsPrincipal"/>.</param>
        /// <exception cref="InvalidOperationException"></exception>
        public static string GetEveSubject(this ClaimsPrincipal principal)
        {
            var id = principal.GetEveIdentity();

            var claim = id?.FindFirst(EveClaims.Issuers.Subject);
            if (claim == null)
            {
                throw new InvalidOperationException($"Subject claim with name [{EveClaims.Issuers.Subject}] is missing.");
            }

            return claim.Value;
        }

        /// <summary>
        /// Return EVE Identity from <see cref="ClaimsIdentity"/> collection.
        /// </summary>
        /// <param name="principal">The <see cref="ClaimsPrincipal"/>.</param>
        public static ClaimsIdentity? GetEveIdentity(this ClaimsPrincipal principal)
        {
            return principal.Identities.FirstOrDefault(x => x.AuthenticationType == EveConstants.AuthenticationType);
        }
    }
}
