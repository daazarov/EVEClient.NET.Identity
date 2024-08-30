using System.Globalization;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.Services;

namespace EVEClient.NET.Identity.Configuration
{
    public class ConfigureEveCookieOptions : IPostConfigureOptions<CookieAuthenticationOptions>
    {
        private readonly string Scheme;
        private readonly string ExternalScheme;

        private readonly EveAuthenticationOptions _options;
        private readonly ILogger<ConfigureEveCookieOptions> _logger;

        public ConfigureEveCookieOptions(IOptions<EveAuthenticationOptions> options, ILogger<ConfigureEveCookieOptions> logger)
        {
            _options = options.Value;
            _logger = logger;

            Scheme = _options.CookieAuthenticationScheme;
            ExternalScheme = _options.CookieExternalAuthenticationScheme;
        }

        public void PostConfigure(string? name, CookieAuthenticationOptions options)
        {
            if (name == Scheme)
            {
                options.Cookie.Name = Scheme;
                options.SlidingExpiration = true;
                options.Events.OnValidatePrincipal = OnValidatePrincipal;
            }
            if (name == ExternalScheme)
            {
                options.Cookie.Name = ExternalScheme;
                options.SlidingExpiration = false;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
            }
        }

        private async Task OnValidatePrincipal(CookieValidatePrincipalContext context)
        {
            if (!context.Properties.ValidateForEveOnline())
            {
                _logger.LogWarning("Missing EVE required data in the AuthenticationProperties, reject principal...");
                context.RejectPrincipal();
                return;
            }

            if (!_options.SaveTokens)
            {
                return;
            }

            // make sure that the token is always up to updated
            var accessToken = context.Properties.GetTokenValue("access_token");
            var refreshToken = context.Properties.GetTokenValue("refresh_token");
            var expiresAtString = context.Properties.GetTokenValue("expires_at");

            if (accessToken.IsMissing() || refreshToken.IsMissing() || !DateTimeOffset.TryParse(expiresAtString, out var expiresAt))
            {
                _logger.LogWarning("Missing token data in the AuthenticationProperties, reject principal...");
                context.RejectPrincipal();
                return;
            }
            
            if (DateTimeOffset.Now >= expiresAt.AddMinutes(-5))
            {
                _logger.LogDebug("Access token in AuthenticationProperties is expired, new token is being requested...");

                var tokenHandlerProvider = context.HttpContext.RequestServices.GetRequiredService<ITokenHandlerProvider>();

                // turn off initialization so that we don't get into an infinite loop during the auntification process
                // instead initialize handler manually using event context without calling AuthenticateAsync
                var tokenHandler = await tokenHandlerProvider.GetAccessTokenHandler(context.HttpContext, context.Scheme.Name, initialize: false);
                if (tokenHandler != null)
                {
                    await tokenHandler.InitializeAsync(context.HttpContext, context.Principal!, context.Properties);
                    var result = await tokenHandler.RenewAccessToken(refreshToken);

                    if (result.Valid)
                    {
                        _logger.LogDebug("Successful access token refresh. New expiration date: {ExpiresAt}", result.ExpiresAt);

                        context.Properties.UpdateTokenValue("access_token", result.AccessToken);
                        context.Properties.UpdateTokenValue("refresh_token", result.RefreshToken);
                        context.Properties.UpdateTokenValue("expires_at", result.ExpiresAt.Value.ToString("o", CultureInfo.InvariantCulture));

                        context.ShouldRenew = true;
                    }
                    else
                    {
                        _logger.LogError(result.Error, "Failed to refresh tokens in the AuthenticationProperties.");
                    }
                }

                _logger.LogError("No refresh token handler is configured to request for the scheme: {Scheme}", context.Scheme.Name);
            }
        }
    }
}
