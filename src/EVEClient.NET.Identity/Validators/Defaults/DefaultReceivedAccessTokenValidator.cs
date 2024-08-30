using System.IdentityModel.Tokens.Jwt;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Defaults;
using EVEClient.NET.Identity.Extensions;

namespace EVEClient.NET.Identity.Validators
{
    public class DefaultReceivedAccessTokenValidator : IReceivedAccessTokenValidator
    {
        protected EveAuthenticationOAuthOptions Options { get; }

        protected HttpClient Backchannel  => Options.Backchannel;

        protected string ClaimsIssuer => Options.ClaimsIssuer!;

        public DefaultReceivedAccessTokenValidator(IOptionsMonitor<EveAuthenticationOAuthOptions> options)
        {
            Options = options.Get(EveAuthenticationCookieDefaults.OAuth.DefaultOAuthAuthenticationSchemeName);
        }

        public async Task<AccessTokenValidationResult> ValidateAsync(string accessToken)
        {
            try
            {
                var response = await Backchannel.GetStringAsync(Options.DiscoveryWebKeysEndpoint);
                var jwk = new JsonWebKeySet(response).Keys.First();

                TokenValidationParameters tokenValidationParams = new TokenValidationParameters
                {
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    // Your application should handle looking for both the host name and the URI in the iss claim
                    // <see href="https://docs.esi.evetech.net/docs/sso/validating_eve_jwt.html"/>
                    ValidIssuers = new List<string> { ClaimsIssuer, ClaimsIssuer.TrimHttpScheme() },
                    ValidAudience = EveConstants.EveAudience,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = jwk
                };

                var validationResult = await new JwtSecurityTokenHandler().ValidateTokenAsync(accessToken, tokenValidationParams);

                return validationResult.IsValid
                    ? AccessTokenValidationResult.Success()
                    : AccessTokenValidationResult.Failed(validationResult.Exception);
            }
            catch (Exception ex)
            {
                return AccessTokenValidationResult.Failed(ex);
            }
        }
    }
}
