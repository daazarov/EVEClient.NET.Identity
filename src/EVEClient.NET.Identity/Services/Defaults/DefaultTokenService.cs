using System.IdentityModel.Tokens.Jwt;

using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.Stores;
using EVEClient.NET.Identity.Utils;
using EVEClient.NET.Identity.Validators;

namespace EVEClient.NET.Identity.Services
{
    public class DefaultTokenService : ITokenService
    {
        private readonly IRefreshTokenStore _refreshTokenStore;
        private readonly IAccessTokenStore _accessTokenStore;
        private readonly ILogger<DefaultTokenService> _logger;
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly IReceivedAccessTokenValidator _tokenValidator;
        private readonly IRemoteTokensHandler _tokenHandler;
        private readonly IOptions<EveAuthenticationOptions> _options;

        private HttpContext Context => _contextAccessor.HttpContext ?? throw new NotSupportedException("HttpContext is not available in the current execution context.");
        private EveAuthenticationOptions Options => _options.Value;

        public DefaultTokenService(
            IRefreshTokenStore refreshTokenStore,
            IAccessTokenStore accessTokenStore,
            ILogger<DefaultTokenService> logger,
            IHttpContextAccessor contextAccessor,
            IReceivedAccessTokenValidator tokenValidator,
            IRemoteTokensHandler tokenHandler,
            IOptions<EveAuthenticationOptions> options)
        {
            _refreshTokenStore = refreshTokenStore;
            _accessTokenStore = accessTokenStore;
            _logger = logger;
            _contextAccessor = contextAccessor;
            _tokenValidator = tokenValidator;
            _tokenHandler = tokenHandler;
            _options = options;
        }

        public async Task<AccessTokenResult> RequestAccessToken()
        {
            var now = DateTimeOffset.Now;

            var authContext = await Context.GetCurrentEveAuthenticationContextAsync();
            if (authContext == null)
            {
                var failureContext = new EveRenewAccessTokenFailureContext
                {
                    Reason = RenewAccessTokenFailureReason.UserNotAuthenticated,
                    HttpContext = Context
                };
                await Options.OAuthEvents.FailRenewAccessToken(failureContext);

                return AccessTokenResult.Failure("EVE user is not authenticated.");
            }

            var accessTokenData = await _accessTokenStore.GetAccessTokenAsync(authContext.AccessTokenReferenceKey);
            if (accessTokenData == null || now >= accessTokenData.ExpiresAt.AddMinutes(-3))
            {
                _logger.LogDebug("Access token is expired or unavailable, a new token is requested.");

                var refreshTokenData = await _refreshTokenStore.GetRefreshTokenAsync(authContext.RefreshTokenReferenceKey);
                if (refreshTokenData == null)
                {
                    var failureContext = new EveRenewAccessTokenFailureContext
                    {
                        Reason = RenewAccessTokenFailureReason.MissingRefreshTokenInStorage,
                        HttpContext = Context,
                        SubjectId = authContext.SubjectId
                    };
                    await Options.OAuthEvents.FailRenewAccessToken(failureContext);

                    return AccessTokenResult.Failure("Unable to renew access token, refresh token not found in the storage.");
                }

                using (var response = await _tokenHandler.RenewAccessToken(refreshTokenData.Value))
                {
                    if (response.Error != null || response.AccessToken.IsMissing() || response.RefreshToken.IsMissing() || response.ExpiresIn.IsMissing())
                    {
                        var tokenResult = PrepareUnsuccessfullAccessTokenResult(response, out var reason);
                        var failureContext = new EveRenewAccessTokenFailureContext
                        { 
                            Reason = reason,
                            OAuthTokenResponse = response,
                            Failure = response.Error,
                            HttpContext = Context,
                            SubjectId = authContext.SubjectId
                        };
                        await Options.OAuthEvents.FailRenewAccessToken(failureContext);

                        return tokenResult;
                    }

                    var validationResult = await _tokenValidator.ValidateAsync(response.AccessToken);
                    if (!validationResult.Succeeded)
                    {
                        var failureContext = new EveRenewAccessTokenFailureContext
                        {
                            Reason = RenewAccessTokenFailureReason.AccessTokenValidationFailed,
                            OAuthTokenResponse = response,
                            HttpContext = Context,
                            Failure = validationResult.Exception,
                            SubjectId = authContext.SubjectId
                        };
                        await Options.OAuthEvents.FailRenewAccessToken(failureContext);

                        return AccessTokenResult.Failure(validationResult.Error, validationResult.Exception);
                    }

                    var renewedAccessTokenData = new AccessTokenData
                    {
                        SubjectId = accessTokenData?.SubjectId ?? authContext.SubjectId,
                        SessionId = accessTokenData?.SessionId ?? authContext.SessionId,
                        TokenType = "access_token",
                        Value = response.AccessToken,
                        CreationTime = DateTimeOffset.Now,
                        ExpiresAt = UnixTimeStampConverter.FromExpiresInUnixTimeStampToExpiresAtDateTime(response.ExpiresIn),
                        GrantedScopes = accessTokenData?.GrantedScopes ?? ExtractScopes(response.AccessToken)
                    };

                    // The refresh_token returned may not be the same as the refresh token submitted.
                    // At some point in the future the EVE SSO will enable refresh token rotation for native applications.
                    // Make sure to update the refresh token in those cases.
                    if (!refreshTokenData.Value.Equals(response.RefreshToken))
                    {
                        refreshTokenData.Value = response.RefreshToken;
                        await _refreshTokenStore.UpdateRefreshTokenAsync(authContext.RefreshTokenReferenceKey, refreshTokenData);
                    }

                    accessTokenData = renewedAccessTokenData;

                    await _accessTokenStore.UpdateAccessTokenAsync(authContext.AccessTokenReferenceKey, accessTokenData);
                }
            }

            return AccessTokenResult.Success(new AccessToken { Value = accessTokenData.Value, Expires = accessTokenData.ExpiresAt, GrantedScopes = accessTokenData.GrantedScopes });
        }

        public async Task RevokeRemoteToken(string tokenType)
        {
            var authContext = await Context.GetCurrentEveAuthenticationContextAsync();
            if (authContext == null)
            {
                throw new InvalidOperationException("User is not authenticated.");
            }

            var token = string.Empty;

            switch (tokenType)
            {
                case "access_token":
                    token = (await _accessTokenStore.GetAccessTokenAsync(authContext.AccessTokenReferenceKey))?.Value;
                    break;
                case "refresh_token":
                    token = (await _refreshTokenStore.GetRefreshTokenAsync(authContext.RefreshTokenReferenceKey))?.Value;
                    break;
            }

            if (token.IsMissing())
            {
                return;
            }

            await _tokenHandler.RevokeRemoteToken(tokenType, token);
        }

        private IReadOnlyList<string> ExtractScopes(string accessToken)
        {
            var jwtValidatedToken = new JwtSecurityTokenHandler().ReadJwtToken(accessToken);

            return jwtValidatedToken.Claims
                    .Where(c => c.Type == EveClaims.Issuers.Scope)
                    .Select(x => x.Value)
                    .ToList();
        }

        private AccessTokenResult PrepareUnsuccessfullAccessTokenResult(OAuthTokenResponse response, out RenewAccessTokenFailureReason reason)
        {
            reason = RenewAccessTokenFailureReason.Unknown;
            
            if (response.Error != null)
            {
                reason = RenewAccessTokenFailureReason.OAuthResponseFailed;
                return AccessTokenResult.Failure("Unable to renew access token.", response.Error);
            }
            else if (response.AccessToken.IsMissing())
            {
                reason = RenewAccessTokenFailureReason.MissingAccessTokenInOAuthResponse;
                return AccessTokenResult.Failure("Failed to retrieve access token.");
            }
            else if (response.RefreshToken.IsMissing())
            {
                reason = RenewAccessTokenFailureReason.MissingRefreshTokenInOAuthResponse;
                return AccessTokenResult.Failure("Failed to retrieve refresh token.");
            }
            else if (response.ExpiresIn.IsMissing())
            {
                reason = RenewAccessTokenFailureReason.MissingExpiresInOAuthResponse;
                return AccessTokenResult.Failure("Failed to retrieve expires_id property from OAuth response.");
            }

            return AccessTokenResult.Failure("Unable to renew access token.");
        }
    }
}
