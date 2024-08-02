using EVEClient.NET;
using EVEClient.NET.Identity.Extensions;
using System.Security.Claims;

namespace EVEClient.NET.Identity.Services
{
    public class EveOnlineUserClaimsEnricher : IUserClaimsTransformator
    {
        private readonly IEsiLogicAccessor _logicAccessor;

        public int Order => -1;

        public EveOnlineUserClaimsEnricher(IEsiLogicAccessor logicAccessor)
        {
            _logicAccessor = logicAccessor;
        }

        public async Task TransformAsync(ClaimsTransformationContext context)
        {
            var characterId = context.IssuedClaims.First(x => x.Type == EveClaims.Issuers.Subject).AsInteger();

            var publicInfo = await _logicAccessor.CharacterLogic.PublicInformation(characterId);
            if (!publicInfo.Success)
            {
                throw new Exception("Unable to retrieve public character data.");
            }

            context.IssuedClaims.Add(new Claim(EveClaims.Custom.Corporation, publicInfo.Data.CorporationId.ToString(), ClaimValueTypes.Integer32, context.ClaimsIssuer));

            if (publicInfo.Data.AlianceId.IsPresent())
            {
                context.IssuedClaims.Add(new Claim(EveClaims.Custom.Alliance, publicInfo.Data.AlianceId.Value.ToString(), ClaimValueTypes.Integer32, context.ClaimsIssuer));
            }
            if (publicInfo.Data.Description.IsPresent())
            {
                context.IssuedClaims.Add(new Claim(EveClaims.Custom.Description, publicInfo.Data.Description, ClaimValueTypes.String, context.ClaimsIssuer));
            }
            if (publicInfo.Data.Title.IsPresent())
            {
                context.IssuedClaims.Add(new Claim(EveClaims.Custom.Title, publicInfo.Data.Title, ClaimValueTypes.String, context.ClaimsIssuer));
            }
        }
    }
}
