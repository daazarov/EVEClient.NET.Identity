using System.Security.Claims;

namespace EVEClient.NET.Identity
{
    public static class IdentityModeSelectors
    {
        private static class Default
        {
            public static ClaimsIdentity? SelectPrimaryIdentity(IEnumerable<ClaimsIdentity> identities)
            {
                ArgumentNullException.ThrowIfNull(identities);

                foreach (ClaimsIdentity identity in identities)
                {
                    if (identity != null)
                    {
                        return identity;
                    }
                }

                return null;
            }
        }


        public static class PrimaryMode
        {
            public static ClaimsIdentity? SelectPrimaryIdentity(IEnumerable<ClaimsIdentity> identities)
            {
                ArgumentNullException.ThrowIfNull(identities);

                return identities.Where(x => x.AuthenticationType == EveConstants.AuthenticationType).FirstOrDefault() ?? Default.SelectPrimaryIdentity(identities);
            }
        }

        public static class SecondaryMode
        {
            public static ClaimsIdentity? SelectPrimaryIdentity(IEnumerable<ClaimsIdentity> identities)
            {
                ArgumentNullException.ThrowIfNull(identities);

                return identities.Where(x => x.AuthenticationType != EveConstants.AuthenticationType).FirstOrDefault();
            }
        }

        public static class MixedMode
        {
            public static ClaimsIdentity? SelectPrimaryIdentity(IEnumerable<ClaimsIdentity> identities)
            {
                ArgumentNullException.ThrowIfNull(identities);

                var eveIdentity = identities.Where(x => x.AuthenticationType == EveConstants.AuthenticationType && x.IsAuthenticated).FirstOrDefault();
                var otherIdentity = identities.Where(x => x.AuthenticationType != EveConstants.AuthenticationType && x.IsAuthenticated).FirstOrDefault();

                return otherIdentity ?? eveIdentity ?? Default.SelectPrimaryIdentity(identities);
            }
        }
    }
}
