using Microsoft.AspNetCore.Authentication.OAuth;
using EVEClient.NET.Identity.Defaults;
using Microsoft.AspNetCore.Http;

namespace EVEClient.NET.Identity.Configuration
{
    public class EveAuthenticationOptions
    {
        public EveAuthenticationOptions()
        {
            OAuthEvents = new OAuthEvents();
        }

        public IdentityMode IdentityMode { get; set; } = IdentityMode.PrimaryIdentity;
        public string ClientId { get; set; } = default!;
        public string ClientSecret { get; set; } = default!;
        public string CookieAuthenticationScheme { get; set; } = EveAuthenticationCookieDefaults.DefaultCookieAuthenticationScheme;
        public string CookieExternalAuthenticationScheme { get; set; } = EveAuthenticationCookieDefaults.DefaultExternalCookieAuthenticationScheme;
        public PathString CallbackPath { get; set; } = EveConstants.OAuthCallbackPath;
        public PathString OAuthFalurePath { get; set; }
        public List<string> Scopes { get; set; } = [];
        public OAuthEvents OAuthEvents { get; }
    }
}
