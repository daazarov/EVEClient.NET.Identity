using EVEClient.NET.Identity.Services;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace EVEClient.NET.Identity
{
    public abstract class UserAccessorBase<TUser> : IEveUserAccessor<TUser>, IFromClaimPrinciple<TUser>
        where TUser : class, IEveUser
    {
        private readonly IHttpContextAccessor _contextAccessor;

        public UserAccessorBase(IHttpContextAccessor contextAccessor)
        {
            ArgumentNullException.ThrowIfNull(contextAccessor);

            _contextAccessor = contextAccessor;
        }

        public virtual TUser? User
        {
            get
            {
                if (_contextAccessor.HttpContext is null)
                {
                    return default;
                }

                return ExtractFromClaimsPrincipal(_contextAccessor.HttpContext.User);
            }
        }

        public abstract TUser? ExtractFromClaimsPrincipal(ClaimsPrincipal principal);
    }
}
