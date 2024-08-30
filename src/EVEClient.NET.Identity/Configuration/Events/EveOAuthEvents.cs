using System.IdentityModel.Tokens.Jwt;

using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.DependencyInjection;

using EVEClient.NET.Identity.Stores;

namespace EVEClient.NET.Identity.Configuration
{
    public class EveOAuthEvents : OAuthEvents
    {
        private Func<EveRenewAccessTokenSuccessContext, Task> _onSuccessRenewAccessToken;

        internal EveOAuthEvents()
        {
            _onSuccessRenewAccessToken = UpdateTokenDataInStorage;
        }

        /// <summary>
        /// Invoked when failed to retrieve access token from internal storage.
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task FailRenewAccessToken(EveRenewAccessTokenFailureContext context) => OnFailedRenewAccessToken(context);

        /// <summary>
        /// Invoked after success refreshing token from external OAuth provider.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task SuccessRenewAccessToken(EveRenewAccessTokenSuccessContext context) => OnSuccessRenewAccessToken(context);

        /// <summary>
        /// Gets or sets the function that is invoked when the FailRenewAccessToken method is invoked.
        /// </summary>
        public Func<EveRenewAccessTokenFailureContext, Task> OnFailedRenewAccessToken { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Gets or adds the function that is invoked when the SuccessRenewAccessToken method is invoked.
        /// </summary>
        /// <remarks>By default, the event call causes the tokens in the storage to be updated.</remarks>
        public Func<EveRenewAccessTokenSuccessContext, Task> OnSuccessRenewAccessToken
        {
            get => _onSuccessRenewAccessToken;
            set => _onSuccessRenewAccessToken += value;
        }

        private async Task UpdateTokenDataInStorage(EveRenewAccessTokenSuccessContext context)
        {
            var accessTokenStore = context.HttpContext.RequestServices.GetRequiredService<IAccessTokenStore>();
            var refreshTokenStore = context.HttpContext.RequestServices.GetRequiredService<IRefreshTokenStore>();
            var keyGenerator = context.HttpContext.RequestServices.GetRequiredService<IStorageKeyGenerator> ();

            await accessTokenStore.UpdateAccessTokenAsync(keyGenerator.GenerateKey(context.SubjectId, context.SessionId, "access_token"), new AccessTokenData
            {
                SubjectId = context.SubjectId,
                SessionId = context.SessionId,
                TokenType = OAuthConstants.TokenTypes.AccessToken,
                Value = context.NewAccessToken,
                CreationTime = DateTimeOffset.Now,
                ExpiresAt = context.ExpiresAt,
                GrantedScopes = ExtractScopes(context.NewAccessToken)
            });

            // The refresh_token returned may not be the same as the refresh token submitted.
            // Make sure to update the refresh token.
            if (!context.OldRefreshToken.Equals(context.NewRefreshToken))
            {
                await refreshTokenStore.UpdateRefreshTokenAsync(keyGenerator.GenerateKey(context.SubjectId, context.SessionId, "refresh_token"), new RefreshTokenData
                {
                    SubjectId = context.SubjectId,
                    SessionId = context.SessionId,
                    CreationTime = DateTimeOffset.Now,
                    TokenType = OAuthConstants.TokenTypes.RefreshToken,
                    Value = context.NewRefreshToken
                });
            }

            IReadOnlyList<string> ExtractScopes(string accessToken)
            {
                var jwtValidatedToken = new JwtSecurityTokenHandler().ReadJwtToken(accessToken);

                return jwtValidatedToken.Claims
                        .Where(c => c.Type == EveClaims.Issuers.Scope)
                        .Select(x => x.Value)
                        .ToList();
            }
        }
    }
}
