using System.Security.Claims;

using Microsoft.AspNetCore.Http;

using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.Services;

namespace EVEClient.NET.Identity
{
    public abstract class EveUserAccessorBase<TUser> : IEveUserAccessor<TUser>, IFromClaimPrinciple<TUser>
        where TUser : class, IEveUser
    {
        private readonly HttpContext _context;

        public bool IsAuthenticated => _context.User.GetEveIdentity()?.IsAuthenticated == true;

        public EveUserAccessorBase(IHttpContextAccessor contextAccessor)
        {
            ArgumentNullException.ThrowIfNull(contextAccessor);

            _context = contextAccessor.HttpContext ?? throw new InvalidOperationException("HttpContext can not be null.");
        }

        public virtual TUser? Current
        {
            get
            {
                 return ExtractFromClaimsPrincipal(_context.User);
            }
        }

        public abstract TUser? ExtractFromClaimsPrincipal(ClaimsPrincipal principal);
    }
}
