using Microsoft.AspNetCore.Http;

namespace EVEClient.NET.Identity
{
    public static class EveConstants
    {
        public static PathString OAuthCallbackPath = "/eve-callback";
        public static PathString PostOAuthCallbackPath = "/signin-eveonline";

        public static string AuthenticationType = "EVE SSO";
        public static string SingOutKey = "eveonline.signout";

        public static string SsoHttpClientName = "SsoEsiHttpClient";

        public static string EVEAudience = "EVE Online";

        public static IEnumerable<string> RequiredClaimNames => new List<string>
        {
            EveClaims.Issuers.Name,
            EveClaims.Issuers.Subject,
            EveClaims.Issuers.IssuedAt,
            EveClaims.Issuers.Expiration,
            EveClaims.Issuers.Scope
        };
    }
}
