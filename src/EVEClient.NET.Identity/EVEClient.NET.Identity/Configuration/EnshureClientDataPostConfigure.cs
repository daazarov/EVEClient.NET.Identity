using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Extensions;

namespace EVEClient.NET.Identity.Configuration
{
    public class EnshureClientDataPostConfigure : IPostConfigureOptions<EveAuthenticationOAuthOptions>
    {
        private readonly string ExternalScheme;

        public EnshureClientDataPostConfigure(IOptions<EveAuthenticationOptions> options)
        {
            ExternalScheme = options.Value.CookieExternalAuthenticationScheme;
        }

        public void PostConfigure(string? name, EveAuthenticationOAuthOptions options)
        {
            if (name == ExternalScheme)
            {
                if (options.ClientId.IsMissing())
                {
                    throw new ArgumentNullException(nameof(options.ClientId), "ClientId is missing.");
                }

                if (options.ClientSecret.IsMissing())
                {
                    throw new ArgumentNullException(nameof(options.ClientSecret), "ClientSecret is missing.");
                }
            }
        }
    }
}
