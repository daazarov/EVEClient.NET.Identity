using EVEClient.NET.Identity.Extensions;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace EVEClient.NET.Identity
{
    public class EveUserAccessor : UserAccessorBase<EveOnlineUser>
    {
        public EveUserAccessor(IHttpContextAccessor contextAccessor) : base(contextAccessor)
        {
        }

        public override EveOnlineUser? ExtractFromClaimsPrincipal(ClaimsPrincipal principal)
        {
            try
            {
                return new EveOnlineUser
                {
                    CharacterId = principal.Claims.First(x => x.Type == EveClaims.Issuers.Subject).AsInteger(),
                    CharacterName = principal.Claims.First(x => x.Type == EveClaims.Issuers.Name).Value,
                    CorporationId = principal.Claims.First(x => x.Type == EveClaims.Custom.Corporation).AsInteger(),
                    AllianceId = principal.Claims.FirstOrDefault(x => x.Type == EveClaims.Custom.Alliance)?.AsInteger(),
                    Description = principal.Claims.FirstOrDefault(x => x.Type == EveClaims.Custom.Description)?.Value,
                    Title = principal.Claims.FirstOrDefault(x => x.Type == EveClaims.Custom.Title)?.Value
                };
            }
            catch
            {
                return null;
            }
        }
    }
}
