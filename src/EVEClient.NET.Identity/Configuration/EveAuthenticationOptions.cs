using Microsoft.AspNetCore.Http;

using EVEClient.NET.Identity.Defaults;

namespace EVEClient.NET.Identity.Configuration
{
    public class EveAuthenticationOptions
    {
        public EveAuthenticationOptions()
        {
            OAuthEvents = new EveOAuthEvents();
            IncludeIssuerClaims = new IssuerClaimsOptions();
        }

        /// <summary>
        /// Gets or sets <see cref="IdentityMode"/> mode.
        /// </summary>
        public IdentityMode IdentityMode { get; set; } = IdentityMode.PrimaryIdentity;

        /// <summary>
        /// Gets or sets an application client id.
        /// </summary>
        /// <remarks>You can get this parameter after creating your application. See more: <see href="https://docs.esi.evetech.net/docs/sso/creating_sso_application.html"/></remarks>
        public string ClientId { get; set; } = default!;

        /// <summary>
        /// Gets or sets an application client secret.
        /// </summary>
        /// <remarks>You can get this parameter after creating your application. See more: <see href="https://docs.esi.evetech.net/docs/sso/creating_sso_application.html"/></remarks>
        public string ClientSecret { get; set; } = default!;

        /// <summary>
        /// Gets or sets application cookie authentication scheme name. The default value: "eveonline.auth".
        /// </summary>
        public string CookieAuthenticationScheme { get; set; } = EveAuthenticationCookieDefaults.DefaultCookieAuthenticationScheme;

        /// <summary>
        /// Gets or sets external cookie authentication scheme name. The default value: "eveonline.external".
        /// </summary>
        /// <remarks>
        /// This cookie is an intermediate cookie. It is created after successful authentication via EVE OAuth2.0 and is used when processing post-oauth behavior.
        /// Removes after processing post-oauth behavior.
        /// </remarks>
        public string CookieExternalAuthenticationScheme { get; set; } = EveAuthenticationCookieDefaults.DefaultExternalCookieAuthenticationScheme;

        /// <summary>
        /// Gets or sets application Callback URL. The default value: "/eve-callback".
        /// </summary>
        /// <remarks>You can setup this parameter while creating your application. See more: <see href="https://docs.esi.evetech.net/docs/sso/creating_sso_application.html"/></remarks>
        public PathString CallbackPath { get; set; } = EveConstants.OAuth.OAuthCallbackPath;

        /// <summary>
        /// Gets or sets path to redirect in case of unsuccessful OAuth authentication. If not specified, the general error will be display.
        /// </summary>
        public PathString OAuthFalurePath { get; set; }

        /// <summary>
        /// Gets or sets ISE scopes necessary for work your application.
        /// </summary>
        public List<string> Scopes { get; set; } = new();

        /// <summary>
        /// Gets the <see cref="EveOAuthEvents"/> used to handle EVE OAuth authentication events.
        /// </summary>
        public EveOAuthEvents OAuthEvents { get; }

        /// <summary>
        /// Allows you to customize additional claims for application identity from provided access token in addition to the mandatory (<see cref="EveConstants.RequiredClaimNames"/>).
        /// </summary>
        public IssuerClaimsOptions IncludeIssuerClaims { get; }
    }
}
