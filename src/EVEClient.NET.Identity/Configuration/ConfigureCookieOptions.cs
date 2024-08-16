using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;

namespace EVEClient.NET.Identity.Configuration
{
    public class ConfigureCookieOptions : IPostConfigureOptions<CookieAuthenticationOptions>
    {
        private readonly string Scheme;
        private readonly string ExternalScheme;

        public ConfigureCookieOptions(IOptions<EveAuthenticationOptions> options)
        {
            Scheme = options.Value.CookieAuthenticationScheme;
            ExternalScheme = options.Value.CookieExternalAuthenticationScheme;
        }

        public void PostConfigure(string? name, CookieAuthenticationOptions options)
        {
            if (name == Scheme)
            {
                options.Cookie.Name = Scheme;
                options.SlidingExpiration = true;
            }
            if (name == ExternalScheme)
            {
                options.Cookie.Name = ExternalScheme;
                options.SlidingExpiration = false;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
            }
        }
    }
}
