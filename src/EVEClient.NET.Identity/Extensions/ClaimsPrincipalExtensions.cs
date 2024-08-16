using System.Security.Claims;

namespace EVEClient.NET.Identity.Extensions
{
    public static class ClaimsPrincipalExtensions
    {
        public static string GetEveSubject(this ClaimsPrincipal principal)
        {
            var id = principal.Identity as ClaimsIdentity;

            var claim = id?.FindFirst(EveClaims.Issuers.Subject);
            if (claim == null)
            {
                throw new InvalidOperationException($"Subject claim with name [{EveClaims.Issuers.Subject}] is missing.");
            }

            return claim.Value;
        }

        public static ClaimsIdentity? GetEveIdentity(this ClaimsPrincipal principal)
        {
            return principal.Identities.FirstOrDefault(x => x.AuthenticationType == EveConstants.AuthenticationType);
        }
    }
}
