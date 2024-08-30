using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using EVEClient.NET.Identity.Configuration;
using EVEClient.NET.Identity.Extensions;
using EVEClient.NET.Identity.OAuth;
using EVEClient.NET.Identity.Stores;
using EVEClient.NET.Identity.Utils;
using EVEClient.NET.Identity.Validators;

namespace EVEClient.NET.Identity.Services
{
    public class DefaultEveAccessTokenHandler : DefaultTokenHandler<AccessTokenResult>, IAccessTokenHandler
    {
        private readonly IReceivedAccessTokenValidator _tokenValidator;

        protected IAccessTokenStore AccessTokenStore { get; }

        protected IRefreshTokenStore RefreshTokenStore { get; }

        protected IStorageKeyGenerator StorageKeyGenerator { get; }

        public override bool Authenticated => base.Authenticated && Principal.Identity.IsEveIdentity();

        public DefaultEveAccessTokenHandler(
            IAccessTokenStore accessTokenStore,
            IRefreshTokenStore refreshTokenStore,
            IStorageKeyGenerator storageKeyGenerator,
            IReceivedAccessTokenValidator tokenValidator,
            ILogger<DefaultEveAccessTokenHandler> logger,
            IOptionsMonitor<EveAuthenticationOAuthOptions> options)
            : base(logger, options)
        { 
            AccessTokenStore = accessTokenStore;
            RefreshTokenStore = refreshTokenStore;
            StorageKeyGenerator = storageKeyGenerator;

            _tokenValidator = tokenValidator;
        }

        public override async Task<AccessTokenResult> HandleTokenRequest()
        {
            if (!Authenticated)
            {
                return AccessTokenResult.Failed("EVE user is not authenticated.");
            }
            
            var subjectId = Principal.GetEveSubject();
            var sessionId = AuthenticationProperties.GetUserSessionId()!;

            var accessTokenKey = StorageKeyGenerator.GenerateKey(subjectId, sessionId, "access_token");
            var refreshTokenKey = StorageKeyGenerator.GenerateKey(subjectId, sessionId, "refresh_token");

            var accessTokenData = await AccessTokenStore.GetAccessTokenAsync(accessTokenKey);
            if (accessTokenData == null || DateTimeOffset.Now >= accessTokenData.ExpiresAt.AddMinutes(-5))
            {
                using (Logger.BeginScope(new Dictionary<string, string> { ["SubjectId"] = subjectId, ["SessionId"] = sessionId }))
                {
                    Logger.LogDebug("Access token is expired or unavailable, new token is being requested...");

                    var refreshToken = (await RefreshTokenStore.GetRefreshTokenAsync(refreshTokenKey))?.Value;

                    // we are ok with the fact that the token can be empty here,
                    // we will process an unsuccessful response in this case and raise event
                    using (var response = await RenewAccessToken(refreshToken ?? string.Empty))
                    {
                        if (!response.Valid)
                        {
                            return AccessTokenResult.Failed($"Unable to renew access token. " +
                                $"Error: {response.OAuthTokenResponse?.Error}; " +
                                $"Error Description: {response.OAuthTokenResponse?.ErrorDescription}", response.Error);
                        }

                        Logger.LogDebug("Successful access token renewal.");

                        return AccessTokenResult.Success(new AccessToken { Value = response.AccessToken, Expires = response.ExpiresAt.Value, GrantedScopes = [.. Options.Scope] });
                    }
                }
            }

            return AccessTokenResult.Success(new AccessToken { Value = accessTokenData.Value, Expires = accessTokenData.ExpiresAt, GrantedScopes = accessTokenData.GrantedScopes });
        }

        public async Task<RenewalAccessTokenResult> RenewAccessToken(string refreshToken)
        {
            if (!Authenticated)
            {
                return RenewalAccessTokenResult.Failed(new AuthenticationFailureException("EVE user is not authenticated."));
            }

            var request = new RefreshAccessTokenRequest
            {
                ClientId = Options.ClientId,
                ClientSecret = Options.ClientSecret,
                RequestUri = new Uri(Options.TokenEndpoint, UriKind.RelativeOrAbsolute),
                RefreshToken = refreshToken,
                Scopes = [.. Options.Scope]
            };

            using (var response = await Backchannel.RefreshAccessTokenAsync(request))
            {
                return response.IsSuccessed
                        ? await ProcessSuccessedTokenResponse(response, request)
                        : await ProcessFailedTokenResponse(response);
            }
        }

        private async Task<RenewalAccessTokenResult> ProcessSuccessedTokenResponse(RefreshAccessTokenResponse response, RefreshAccessTokenRequest request)
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

                return RenewalAccessTokenResult.Failed(response, validationResult.Exception);
            }
            else
            {
                await Events.SuccessRenewAccessToken(new EveRenewAccessTokenSuccessContext
                {
                    HttpContext = HttpContext,
                    SubjectId = Principal!.GetEveSubject(),
                    OldRefreshToken = request.RefreshToken,
                    NewAccessToken = response.AccessToken!,
                    NewRefreshToken = response.RefreshToken!,
                    ExpiresAt = UnixTimeStampConverter.FromExpiresInToExpiresAtDateTime(response.ExpiresIn!),
                    SessionId = AuthenticationProperties!.GetUserSessionId()!
                });

                return RenewalAccessTokenResult.Success(response);
            }
        }

        private async Task<RenewalAccessTokenResult> ProcessFailedTokenResponse(RefreshAccessTokenResponse response)
        {
            Logger.LogError("Failed to refresh access token. Error: {Error}; Error Description: {Description}", response.Error, response.ErrorDescription);

            await Events.FailRenewAccessToken(new EveRenewAccessTokenFailureContext
            {
                HttpContext = HttpContext,
                OAuthTokenResponse = response,
                SubjectId = Principal!.GetEveSubject(),
                Reason = response.Error ?? response.ErrorDescription ?? "Unknown"
            });

            return RenewalAccessTokenResult.Failed(response);
        }
    }
}
