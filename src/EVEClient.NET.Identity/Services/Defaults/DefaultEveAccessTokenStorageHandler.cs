using System.IdentityModel.Tokens.Jwt;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.Stores;
using EVEClient.NET.Identity.Validators;
using System.Diagnostics.CodeAnalysis;

namespace EVEClient.NET.Identity.Services
{
    public class DefaultEveAccessTokenStorageHandler : BaseEveAccessTokenHandler
    {
        /// <summary>
        /// Gets the <see cref="IAccessTokenStore"/>.
        /// </summary>
        protected IAccessTokenStore AccessTokenStore { get; }

        /// <summary>
        /// Gets the <see cref="IRefreshTokenStore"/>.
        /// </summary>
        protected IRefreshTokenStore RefreshTokenStore { get; }

        public DefaultEveAccessTokenStorageHandler(
            IAccessTokenStore accessTokenStore,
            IRefreshTokenStore refreshTokenStore,
            ITokenHandlerProvider tokenHandlerProvider,
            IReceivedAccessTokenValidator tokenValidator,
            ILogger<DefaultEveAccessTokenStorageHandler> logger,
            IOptionsMonitor<EveAuthenticationOAuthOptions> options)
            : base(tokenValidator, tokenHandlerProvider, logger, options)
        {
            AccessTokenStore = accessTokenStore;
            RefreshTokenStore = refreshTokenStore;
        }

        protected override async Task<AccessTokenResult> HandleRequestTokenAsync()
        {
            var accessTokenKey = AuthenticationProperties!.GetAccessTokenStorageKey();
            if (accessTokenKey.IsMissing())
            {
                throw new InvalidOperationException("Missing access token storage key in the AuthenticationProperties.");
            }

            var accessTokenData = await AccessTokenStore.GetAccessTokenAsync(accessTokenKey);
            if (accessTokenData == null )
            {
                return AccessTokenResult.Empty();
            }

            return AccessTokenResult.Success(new AccessToken { Value = accessTokenData.Value, ExpiresAt = accessTokenData.ExpiresAt, GrantedScopes = accessTokenData.GrantedScopes });
        }

        protected override async Task<bool> HandleStoreTokensAsync(AccessTokenStoreRequest request)
        {
            var accessToken = new AccessTokenData
            {
                SubjectId = SubjectId!,
                TokenType = OAuthConstants.TokenTypes.AccessToken,
                Value = request.AccessToken,
                GrantedScopes = request.GrantedScopes,
                CreationTime = request.IssuedAt,
                ExpiresAt = request.ExpiresAt,
                SessionId = SessionId!,
            };

            var refreshToken = new RefreshTokenData
            {
                SubjectId = SubjectId!,
                TokenType = OAuthConstants.TokenTypes.RefreshToken,
                Value = request.RefreshToken,
                SessionId = SessionId!,
                CreationTime = request.IssuedAt,
            };

            AuthenticationProperties!.StoreAccessTokenStorageKey(await AccessTokenStore.StoreAccessTokenAsync(accessToken));
            AuthenticationProperties!.StoreRefreshTokenStorageKey(await RefreshTokenStore.StoreRefreshTokenAsync(refreshToken));

            return true;
        }

        protected override async Task HandleSuccessedRefreshToken(string accessToken, string refreshToken, DateTimeOffset expiresAt)
        {
            var accessTokenKey = AuthenticationProperties?.GetAccessTokenStorageKey();
            var refreshTokenKey = AuthenticationProperties?.GetRefreshTokenStorageKey();

            if (accessTokenKey.IsMissing())
            {
                throw new InvalidOperationException("Missing access token storage key in the AuthenticationProperties.");
            }

            if (refreshTokenKey.IsMissing())
            {
                throw new InvalidOperationException("Missing refresh token storage key in the AuthenticationProperties.");
            }

            await AccessTokenStore.UpdateAccessTokenAsync(accessTokenKey, new AccessTokenData
            {
                SubjectId = SubjectId!,
                SessionId = SessionId!,
                TokenType = OAuthConstants.TokenTypes.AccessToken,
                Value = accessToken,
                CreationTime = DateTimeOffset.Now,
                ExpiresAt = expiresAt,
                GrantedScopes = ExtractScopes(accessToken)
            });

            // The refresh_token returned may not be the same as the refresh token submitted.
            // Make sure to update the refresh token.
            var originalRefreshToken = (await RefreshTokenStore.GetRefreshTokenAsync(refreshTokenKey))?.Value;

            if (!refreshToken.Equals(originalRefreshToken))
            {
                await RefreshTokenStore.UpdateRefreshTokenAsync(refreshTokenKey, new RefreshTokenData
                {
                    SubjectId = SubjectId!,
                    SessionId = SessionId!,
                    CreationTime = DateTimeOffset.Now,
                    TokenType = OAuthConstants.TokenTypes.RefreshToken,
                    Value = refreshToken
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
