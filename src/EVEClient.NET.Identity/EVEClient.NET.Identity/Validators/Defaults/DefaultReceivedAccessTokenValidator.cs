using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace EVEClient.NET.Identity.Validators
{
    public class DefaultReceivedAccessTokenValidator : IReceivedAccessTokenValidator
    {
        protected EveAuthenticationOAuthOptions Options { get; }

        protected HttpClient Backchannel { get; }

        protected string ClaimsIssuer { get; }

        public DefaultReceivedAccessTokenValidator(IOptionsMonitor<EveAuthenticationOAuthOptions> options, IHttpClientFactory httpClientFactory)
        {
            Options = options.CurrentValue;
            Backchannel = httpClientFactory.CreateClient(EveConstants.SsoHttpClientName);
            ClaimsIssuer = Options.ClaimsIssuer!;
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
                    ValidAudience = EveConstants.EVEAudience,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = jwk
                };

                var claims = new JwtSecurityTokenHandler().ValidateToken(accessToken, tokenValidationParams, out var validatedToken);

                if (claims != null && validatedToken != null)
                {
                    return AccessTokenValidationResult.Success();
                }
                else
                {
                    return AccessTokenValidationResult.Failed("Failed to validate EVE security token.");
                }
            }
            catch (Exception ex)
            {
                return AccessTokenValidationResult.Failed(ex);
            }
        }
    }
}
