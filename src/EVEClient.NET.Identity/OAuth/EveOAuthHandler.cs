using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Encodings.Web;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Utils;
using EVEClient.NET.Identity.Validators;

namespace EVEClient.NET.Identity.OAuth
{
    public class EveOAuthHandler : OAuthHandler<EveAuthenticationOAuthOptions>
    {
        private readonly IReceivedAccessTokenValidator _accessTokenValidator;

        public EveOAuthHandler(
            IReceivedAccessTokenValidator accessTokenValidator,
            IOptionsMonitor<EveAuthenticationOAuthOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder)
            : base(options, logger, encoder)
        {
            _accessTokenValidator = accessTokenValidator;
        }

        protected override Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            try
            {
                return base.HandleRemoteAuthenticateAsync();
            }
            catch (SecurityTokenException ex)
            {
                return Task.FromResult(HandleRequestResult.Fail(ex));
            }
        }

        protected override async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            var validationResult = await _accessTokenValidator.ValidateAsync(tokens.AccessToken!);
            if (!validationResult.Succeeded)
            {
                throw validationResult.Exception ?? new SecurityTokenException(validationResult.Error);
            }

            var jwtSecurityToken = new JwtSecurityTokenHandler().ReadJwtToken(tokens.AccessToken);
            identity.AddClaims(jwtSecurityToken.Claims);

            var authTokens = properties.GetTokens().ToList();

            var issuedAt = UnixTimeStampConverter.UnixTimeStampToDateTime(jwtSecurityToken.Claims.First(x => x.Type.Equals(EveClaims.Issuers.IssuedAt, StringComparison.OrdinalIgnoreCase)).Value);
            authTokens.Add(new AuthenticationToken
            {
                Name = "issued_at",
                Value = issuedAt.ToString("o", CultureInfo.InvariantCulture)
            });

            properties.StoreTokens(authTokens);

            return await base.CreateTicketAsync(identity, properties, tokens);
        }
    }
}
