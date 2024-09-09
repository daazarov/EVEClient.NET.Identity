using Microsoft.AspNetCore.Http;

using EVEClient.NET.Identity.Defaults;

namespace EVEClient.NET.Identity.Configuration
{
    public class EveAuthenticationOptions
    {
        private readonly List<TokenHandlerConfiguration> _tokenHandlerConfigurations = new();
        
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
        /// Defines whether EVE access and refresh tokens should be stored in the <see cref="Microsoft.AspNetCore.Authentication.AuthenticationProperties"/> after a successful authentication. 
        /// Otherwise, <see cref="Stores.IAccessTokenStore"/> and <see cref="Stores.IRefreshTokenStore"/> storages will be used.
        /// </summary>
        /// <remarks>This property is set to <c>true</c> by default.</remarks>
        public bool UseCookieStorage { get; set; } = true;

        /// <summary>
        /// Gets the <see cref="EveOAuthEvents"/> used to handle EVE OAuth authentication events.
        /// </summary>
        public EveOAuthEvents OAuthEvents { get; }

        /// <summary>
        /// Allows you to customize additional claims for application identity from provided access token in addition to the mandatory (<see cref="EveConstants.RequiredClaimNames"/>).
        /// </summary>
        public IssuerClaimsOptions IncludeIssuerClaims { get; }

        /// <summary>
        /// Returns the handler configuration.
        /// </summary>
        public IEnumerable<TokenHandlerConfiguration> TokenHandlerConfigurations => _tokenHandlerConfigurations;

        /// <summary>
        /// Adds an <see cref="TokenHandlerConfiguration"/>.
        /// </summary>
        /// <param name="configure">Configures the handler.</param>
        /// <exception cref="InvalidOperationException"></exception>
        public void AddTokenHandler(Action<TokenHandlerConfiguration> configure)
        {
            ArgumentNullException.ThrowIfNull(configure);

            var config = new TokenHandlerConfiguration();
            configure(config);

            config.Validate();

            if (_tokenHandlerConfigurations.Contains(config))
            {
                throw new InvalidOperationException($"Token handler configuration with token type [{config.TokenType}] for scheme [{config.Scheme}] already exists.");
            }

            _tokenHandlerConfigurations.Add(config);
        }
    }
}
