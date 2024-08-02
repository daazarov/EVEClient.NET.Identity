using Microsoft.AspNetCore.Authentication;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

namespace EVEClient.NET.Identity.Services
{
    public class PostOAuthSingInBehaviorResult : PostOAuthBehaviorResult
    {
        public AuthenticationProperties? AuthenticationProperties { get; private set; }
        public ClaimsPrincipal? Principal { get; private set; }

        [MemberNotNullWhen(true, nameof(AuthenticationProperties), nameof(Principal))]
        public override bool Succeeded => base.Succeeded;

        public static PostOAuthSingInBehaviorResult Success(ClaimsPrincipal principal, AuthenticationProperties properties)
        {
            return new PostOAuthSingInBehaviorResult { Principal = principal, AuthenticationProperties = properties };
        }

        public static PostOAuthSingInBehaviorResult Failed(Exception exception, AuthenticationProperties? properties = null)
        {
            return new PostOAuthSingInBehaviorResult { Error = exception, };
        }
    }
}
