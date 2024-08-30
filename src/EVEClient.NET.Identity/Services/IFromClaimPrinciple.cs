using System.Security.Claims;

namespace EVEClient.NET.Identity.Services
{
    public interface IFromClaimPrinciple<TUser> where TUser : class, IEveUser
    {
        /// <summary>
        /// Converts the value of user claims to an object describing the user.
        /// </summary>
        /// <param name="principal">The <see cref="ClaimsPrincipal"/>.</param>
        TUser? ExtractFromClaimsPrincipal(ClaimsPrincipal principal);
    }
}
