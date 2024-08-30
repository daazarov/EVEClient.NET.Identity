using Microsoft.AspNetCore.Http;

namespace EVEClient.NET.Identity
{
    public static class EveConstants
    {
        public static class OAuth
        {
            public static PathString OAuthCallbackPath = "/eve-callback";
            public static PathString PostOAuthCallbackPath = "/signin-eveonline";
        }

        public static class TokenHandler
        {
            public const string AccessTokenHandler = "token.handler.access";
            public const string RefreshTokenHandler = "token.handler.refresh";
        }

        public static string EveAudience = "EVE Online";
        public static string AuthenticationType = "EVE Online";
        public static string SingOutKey = "eveonline.signout";

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
