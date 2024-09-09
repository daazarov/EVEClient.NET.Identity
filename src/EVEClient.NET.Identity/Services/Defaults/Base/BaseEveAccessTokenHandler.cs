using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.OAuth;
using EVEClient.NET.Identity.Utils;
using EVEClient.NET.Identity.Validators;

namespace EVEClient.NET.Identity.Services
{
    public abstract class BaseEveAccessTokenHandler : BaseEveTokenHandler<AccessTokenResult>, IAccessTokenHandler, IStoreTokenHandler<AccessTokenStoreRequest>
    {
        private readonly IReceivedAccessTokenValidator _tokenValidator;
        private readonly ITokenHandlerProvider _tokenHandlerProvider;

        private const string NotAuthenticatedError = "The EVE user context can't be considered valid after initialization or token handler is not initialized.";

        /// <summary>
        /// Allows derived types to handle requesting of token.
        /// </summary>
        /// <returns>The <see cref="AccessTokenResult"/> instance.</returns>
        protected abstract Task<AccessTokenResult> HandleRequestTokenAsync();

        /// <summary>
        /// Allows derived types to handle storing of token.
        /// </summary>
        /// <param name="request"></param>
        protected abstract Task<bool> HandleStoreTokensAsync(AccessTokenStoreRequest request);

        /// <summary>
        /// Allows derived types to handle successful refreshing of the access token.
        /// </summary>
        /// <param name="accessToken">The recieved access token.</param>
        /// <param name="refreshToken">The recieved refresh token.</param>
        /// <param name="expiresAt">The expiration date time of token.</param>
        /// <returns>The <see cref="Task"/>.</returns>
        protected abstract Task HandleSuccessedRefreshToken(string accessToken, string refreshToken, DateTimeOffset expiresAt);

        public BaseEveAccessTokenHandler(
            IReceivedAccessTokenValidator tokenValidator,
            ITokenHandlerProvider tokenHandlerProvider,
            ILogger logger,
            IOptionsMonitor<EveAuthenticationOAuthOptions> options)
            : base(logger, options)
        { 
            _tokenValidator = tokenValidator;
            _tokenHandlerProvider = tokenHandlerProvider;
        }

        public Task<bool> StoreTokensAsync(AccessTokenStoreRequest request)
        {
            if (!IsAuthenticated)
            {
                Logger.LogWarning("Can not store the tokens. The EVE user context can't be considered valid after initialization or token handler is not initialized.");
                return Task.FromResult(false);
            }

            if (!request.SubjectId.Equals(SubjectId))
            {
                throw new InvalidOperationException("The user authentication context does not match the user for whom token storing is requested.");
            }

            return HandleStoreTokensAsync(request);
        }

        public sealed override async Task<AccessTokenResult> RequestTokenAsync()
        {
            if (!IsAuthenticated)
            {
                return AccessTokenResult.Failed(NotAuthenticatedError);
            }

            var result = await HandleRequestTokenAsync();

            // We also want to try to handle the case when the token could not be returned.
            // Probably the storage access token entry is simply expired and deleted,
            // but we can still successfully request a new one if refresh token is still exists.
            if (!result.TryGetToken(out _) ||
                (result.TryGetToken(out var accessToken) && DateTimeOffset.UtcNow >= accessToken.ExpiresAt.AddMinutes(-5)))
            {
                Logger.LogDebug("Access token is not available or expired, trying to refresh access token...");

                using (var refreshingResult = await RefreshAccessToken())
                {
                    if (refreshingResult.Valid)
                    {
                        await HandleSuccessedRefreshToken(refreshingResult.AccessToken, refreshingResult.RefreshToken, refreshingResult.ExpiresAt.Value);

                        return AccessTokenResult.Success(new AccessToken { Value = refreshingResult.AccessToken, ExpiresAt = refreshingResult.ExpiresAt.Value, GrantedScopes = [.. Options.Scope] });
                    }
                    
                    return AccessTokenResult.Failed($"Unable to renew access token. " +
                        $"Error: {refreshingResult.OAuthTokenResponse?.Error}; " +
                        $"Error Description: {refreshingResult.OAuthTokenResponse?.ErrorDescription}", refreshingResult.Error);
                }
            }

            return result;
        }

        public async Task<RefreshAccessTokenResult> RefreshAccessToken()
        {
            if (!IsAuthenticated)
            {
                return RefreshAccessTokenResult.Failed(new AuthenticationFailureException(NotAuthenticatedError));
            }

            var handler = await _tokenHandlerProvider.GetRefreshTokenHandler(HttpContext, Scheme);
            if (handler == null)
            {
                throw new InvalidOperationException($"No refresh token handler is configured to request for the scheme: {Scheme}");
            }

            await handler.InitializeAsync(HttpContext, Principal, AuthenticationProperties);

            var result = await handler.RequestTokenAsync();

            return result.TryGetToken(out var token)
                ? await HandleRefreshAccessToken(token)
                : RefreshAccessTokenResult.Failed(result.Error ?? new Exception(result.ErrorMessage));
        }

        protected virtual async Task<RefreshAccessTokenResult> HandleRefreshAccessToken(string refreshToken)
        {
            var request = new RefreshAccessTokenRequest
            {
                ClientId = Options.ClientId,
                ClientSecret = Options.ClientSecret,
                RequestUri = new Uri(Options.TokenEndpoint, UriKind.RelativeOrAbsolute),
                RefreshToken = refreshToken,
                Scopes = [.. Options.Scope]
            };

            var response = await Backchannel.RefreshAccessTokenAsync(request);

            return response.IsSuccessed
                    ? await ProcessSuccessedTokenResponse(response, request)
                    : await ProcessFailedTokenResponse(response);
        }

        private async Task<RefreshAccessTokenResult> ProcessSuccessedTokenResponse(RefreshAccessTokenResponse response, RefreshAccessTokenRequest request)
        {
            var validationResult = await _tokenValidator.ValidateAsync(response.AccessToken!);

            if (!validationResult.Succeeded)
            {
                await Events.FailRenewAccessToken(new EveRenewAccessTokenFailureContext
                {
                    HttpContext = HttpContext,
                    OAuthTokenResponse = response,
                    SubjectId = Principal!.GetEveSubject(),
                    Reason = validationResult.Error,
                    Failure = validationResult.Exception
                });

                Logger.LogError(validationResult.Exception, "Failed to refresh access token. Recieved access token is not valid.");

                return RefreshAccessTokenResult.Failed(response, validationResult.Exception);
            }
            else
            {
                var expiresAt = UnixTimeStampConverter.FromExpiresInToExpiresAtDateTime(response.ExpiresIn!);

                await Events.SuccessRenewAccessToken(new EveRenewAccessTokenSuccessContext
                {
                    HttpContext = HttpContext,
                    SubjectId = SubjectId!,
                    OldRefreshToken = request.RefreshToken,
                    NewAccessToken = response.AccessToken!,
                    NewRefreshToken = response.RefreshToken!,
                    ExpiresAt = expiresAt,
                    SessionId = SessionId!
                });

                Logger.LogDebug("Successful access token refresh. New expiration date: {ExpiresAt}", expiresAt);

                return RefreshAccessTokenResult.Success(response);
            }
        }

        private async Task<RefreshAccessTokenResult> ProcessFailedTokenResponse(RefreshAccessTokenResponse response)
        {
            Logger.LogError("Failed to refresh access token. Error: {Error}; Error Description: {Description}", response.Error, response.ErrorDescription);

            await Events.FailRenewAccessToken(new EveRenewAccessTokenFailureContext
            {
                HttpContext = HttpContext,
                OAuthTokenResponse = response,
                SubjectId = SubjectId!,
                Reason = response.Error ?? response.ErrorDescription ?? "Unknown"
            });

            return RefreshAccessTokenResult.Failed(response);
        }
    }
}
