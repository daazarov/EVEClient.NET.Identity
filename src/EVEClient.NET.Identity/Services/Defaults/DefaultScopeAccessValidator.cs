using System.IdentityModel.Tokens.Jwt;

namespace EVEClient.NET.Identity.Services
{
    public class DefaultScopeAccessValidator : IScopeAccessValidator
    {
        public Task<bool> ValidateScopeAccess(string token, string scope)
        {
            var jwtToken = new JwtSecurityTokenHandler().ReadJwtToken(token);

            var scopes = jwtToken.Claims
                .Where(x => x.Type == EveClaims.Issuers.Scope)
                .Select(x => x.Value)
                .ToArray();

            return Task.FromResult(scopes.Contains(scope));
        }
    }
}
