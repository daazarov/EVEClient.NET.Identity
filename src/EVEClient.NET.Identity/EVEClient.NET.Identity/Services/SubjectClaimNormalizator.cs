using EVEClient.NET.Identity.Extensions;
using System.Security.Claims;

namespace EVEClient.NET.Identity.Services
{
    public class SubjectClaimNormalizator : IUserClaimsTransformator
    {
        public int Order => -2;

        public Task TransformAsync(ClaimsTransformationContext context)
        {
            var subjectClaim = context.IssuedClaims.First(x => x.Type == EveClaims.Issuers.Subject);

            if (subjectClaim.Value != subjectClaim.Value.EnshureEveSubjectNormalized())
            {
                var normalizedSubjectClaim = new Claim(EveClaims.Issuers.Subject, subjectClaim.Value.EnshureEveSubjectNormalized(), ClaimValueTypes.String, subjectClaim.Issuer);

                context.IssuedClaims.Remove(subjectClaim);
                context.IssuedClaims.Add(normalizedSubjectClaim);
            }

            return Task.CompletedTask;
        }
    }
}
