using System.Security.Claims;

namespace EVEClient.NET.Identity.Services
{
    public interface IFromClaimPrinciple<TUser> where TUser : class, IEveUser
    {
        TUser? ExtractFromClaimsPrincipal(ClaimsPrincipal principal);
    }
}
