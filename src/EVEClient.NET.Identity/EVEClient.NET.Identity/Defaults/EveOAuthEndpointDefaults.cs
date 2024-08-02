using EVEClient.NET.Extensions;

namespace EVEClient.NET.Identity.Defaults
{
    public class EveOAuthEndpointDefaults
    {
        private static string DiscoveryWebKeysPostfix = "oauth/jwks";
        private static string DiscoveryConfigurationPostfix = ".well-known/oauth-authorization-server";
        private static string RevokeTokenPostfix = "v2/oauth/revoke";
        private static string GetTokenPostfix = "v2/oauth/token";
        private static string AuthorizePostfix = "v2/oauth/authorize";

        internal static class Tranquility
        {
            public static string AuthorizationSsoBaseUrl = "https://login.eveonline.com";
            public static string Issuer = AuthorizationSsoBaseUrl;
            public static string DiscoveryWebKeysEndpoint = AuthorizationSsoBaseUrl + DiscoveryWebKeysPostfix.EnsureLeadingSlash();
            public static string DiscoveryConfigurationEndpoint = AuthorizationSsoBaseUrl + DiscoveryConfigurationPostfix.EnsureLeadingSlash();
            public static string RevokeTokenEndpoint = AuthorizationSsoBaseUrl + RevokeTokenPostfix.EnsureLeadingSlash();
            public static string TokenEndpoint = AuthorizationSsoBaseUrl +  GetTokenPostfix.EnsureLeadingSlash();
            public static string AuthorizationEndpoint = AuthorizationSsoBaseUrl + AuthorizePostfix.EnsureLeadingSlash();
        }

        internal static class Singularity
        {
            public static string AuthorizationSsoBaseUrl = "https://sisilogin.testeveonline.com";
            public static string Issuer = AuthorizationSsoBaseUrl;
            public static string DiscoveryWebKeysEndpoint = AuthorizationSsoBaseUrl + DiscoveryWebKeysPostfix.EnsureLeadingSlash();
            public static string DiscoveryConfigurationEndpoint = AuthorizationSsoBaseUrl + DiscoveryConfigurationPostfix.EnsureLeadingSlash();
            public static string RevokeTokenEndpoint = AuthorizationSsoBaseUrl + RevokeTokenPostfix.EnsureLeadingSlash();
            public static string TokenEndpoint = AuthorizationSsoBaseUrl + GetTokenPostfix.EnsureLeadingSlash();
            public static string AuthorizationEndpoint = AuthorizationSsoBaseUrl + AuthorizePostfix.EnsureLeadingSlash();
        }
    }
}
