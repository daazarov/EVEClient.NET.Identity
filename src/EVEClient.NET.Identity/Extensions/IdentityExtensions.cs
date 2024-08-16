using System.Diagnostics.CodeAnalysis;
using System.Security.Principal;

namespace EVEClient.NET.Identity.Extensions
{
    public static class IdentityExtensions
    {
        public static bool IsEveIdentity([NotNullWhen(true)] this IIdentity? identity)
        {
            if (identity == null)
            {
                return false;
            }

            return identity.AuthenticationType == EveConstants.AuthenticationType;
        }
    }
}
