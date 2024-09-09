using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Extensions;

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

        private Task OnValidatePrincipal(CookieValidatePrincipalContext context)
        {
            using (_logger.BeginScope(new Dictionary<string, string> { ["SubjectId"] = context.Principal!.GetEveSubject() }))
            {
                if (!context.Properties.ValidateSessionIdForEveOnline())
                {
                    _logger.LogError("Missing EVE session id in the AuthenticationProperties, reject principal...");
                    context.RejectPrincipal();
                    return Task.CompletedTask;
                }

                if (_options.UseCookieStorage)
                {
                    if (!context.Properties.ValidateCookieTokensForEveOnline())
                    {
                        _logger.LogError("Missing token data in the AuthenticationProperties, reject principal...");
                        context.RejectPrincipal();
                        return Task.CompletedTask;
                    }
                }
                else
                {
                    if (!context.Properties.ValidateStorageKeysForEveOnline())
                    {
                        _logger.LogError("Missing token storage keys in the AuthenticationProperties, reject principal...");
                        context.RejectPrincipal();
                        return Task.CompletedTask;
                    }
                }
            }

            return Task.CompletedTask;
        }
    }
}
