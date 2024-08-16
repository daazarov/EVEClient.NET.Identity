using System.Security.Claims;

using EVEClient.NET.Identity.Extensions;

namespace EVEClient.NET.Identity.Services
{
    public class EveOnlineUserClaimsEnricher : IUserClaimsTransformator
    {
        private readonly IEsiLogicAccessor _logicAccessor;

        public EveOnlineUserClaimsEnricher(IEsiLogicAccessor logicAccessor)
        {
            _logicAccessor = logicAccessor;
        }

        public async Task TransformAsync(ClaimsTransformationContext context)
        {
            var characterId = int.Parse(context.IssuedClaims.First(x => x.Type == EveClaims.Issuers.Subject).Value.EnshureEveSubjectNormalized());

            var publicInfo = await _logicAccessor.CharacterLogic.PublicInformation(characterId);
            var portrait = await _logicAccessor.CharacterLogic.Portrait(characterId);

            if (!publicInfo.Success || !portrait.Success)
            {
                throw new Exception("Unable to retrieve public character data.");
            }

            context.IssuedClaims.Add(new Claim(EveClaims.Custom.Corporation, publicInfo.Data.CorporationId.ToString(), ClaimValueTypes.Integer32, context.ClaimsIssuer));

            if (publicInfo.Data.AlianceId.IsPresent())
            {
                context.IssuedClaims.Add(new Claim(EveClaims.Custom.Alliance, publicInfo.Data.AlianceId.Value.ToString(), ClaimValueTypes.Integer32, context.ClaimsIssuer));
            }

            if (portrait.Data.px64x64.IsPresent())
            {
                context.IssuedClaims.Add(new Claim(EveClaims.Custom.Portrait, portrait.Data.px64x64.RemoveQueryStringByKey("size"), ClaimValueTypes.String, context.ClaimsIssuer));
            }
        }
    }
}
