namespace EVEClient.NET.Identity.Defaults
{
    public class EveAuthenticationCookieDefaults
    {
        public static string DefaultExternalCookieAuthenticationScheme = "eveonline.external";
        public static string DefaultCookieAuthenticationScheme = "eveonline.auth";

        public static class OAuth
        {
            public static string DefaultOAuthSchemeName = "EVEOnline";
            public static string DefaultOAuthSchemeDisplayName = "EVEOnline";
        }
    }
}
